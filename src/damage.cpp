#include "damage.h"
#include "hooks.h"

#include <steam/steam_api.h>

#include <algorithm>
#include <atomic>
#include <limits>

static CSteamID g_lobbyId = k_steamIDNil;
static std::atomic<int64_t> g_pendingBroadcastDamage{0};

class LobbyTracker
{
public:
    STEAM_CALLBACK(LobbyTracker, OnLobbyEnter, LobbyEnter_t);
    STEAM_CALLBACK(LobbyTracker, OnLobbyChatUpdate, LobbyChatUpdate_t);
    STEAM_CALLBACK(
        LobbyTracker, OnSessionRequest,
        SteamNetworkingMessagesSessionRequest_t);
    STEAM_CALLBACK(
        LobbyTracker, OnSessionFailed,
        SteamNetworkingMessagesSessionFailed_t);
};

void LobbyTracker::OnLobbyEnter(LobbyEnter_t* event)
{
    if (event->m_EChatRoomEnterResponse == k_EChatRoomEnterResponseSuccess)
        g_lobbyId = CSteamID(event->m_ulSteamIDLobby);
    else
        g_lobbyId = k_steamIDNil;
}

void LobbyTracker::OnLobbyChatUpdate(LobbyChatUpdate_t* event)
{
    ISteamUser* user = SteamUser();
    if (!user)
        return;

    const bool localUserChanged =
        CSteamID(event->m_ulSteamIDUserChanged) == user->GetSteamID();
    const bool left =
        (event->m_rgfChatMemberStateChange &
         (k_EChatMemberStateChangeLeft |
          k_EChatMemberStateChangeDisconnected |
          k_EChatMemberStateChangeKicked)) != 0;
    if (localUserChanged && left)
        g_lobbyId = k_steamIDNil;
}

void LobbyTracker::OnSessionRequest(
    SteamNetworkingMessagesSessionRequest_t* event)
{
    if (ISteamNetworkingMessages* messages = SteamNetworkingMessages())
        messages->AcceptSessionWithUser(event->m_identityRemote);
}

void LobbyTracker::OnSessionFailed(
    SteamNetworkingMessagesSessionFailed_t*)
{
}

static LobbyTracker g_lobbyTracker;

SharedDamageLobbyPresence GetSharedDamageLobbyPresence()
{
    if (!g_lobbyId.IsValid())
        return SharedDamageLobbyPresence::Unknown;

    ISteamMatchmaking* matchmaking = SteamMatchmaking();
    if (!matchmaking)
        return SharedDamageLobbyPresence::Unknown;

    const int memberCount = matchmaking->GetNumLobbyMembers(g_lobbyId);
    if (memberCount < 0)
        return SharedDamageLobbyPresence::Unknown;
    if (memberCount < 2)
        return SharedDamageLobbyPresence::NoRemoteMembers;
    return SharedDamageLobbyPresence::RemoteMembersPresent;
}

void BroadcastDamage(int32_t damage)
{
    if (damage <= 0)
        return;

    if (!IsSameWorldActive())
        return;

    g_pendingBroadcastDamage.fetch_add(damage, std::memory_order_release);
}

void DiscardPendingBroadcastDamage()
{
    g_pendingBroadcastDamage.store(0, std::memory_order_release);
}

void FlushBroadcastDamage()
{
    const int64_t pending =
        g_pendingBroadcastDamage.exchange(0, std::memory_order_acq_rel);
    if (pending <= 0)
        return;

    const DamagePacket packet{
        DAMAGE_PACKET_MAGIC,
        static_cast<int32_t>(std::min<int64_t>(
            pending, std::numeric_limits<int32_t>::max()))};

    if (!IsSameWorldActive())
        return;

    if (!g_lobbyId.IsValid())
        return;

    ISteamMatchmaking* matchmaking = SteamMatchmaking();
    ISteamUser* user = SteamUser();
    ISteamNetworkingMessages* messages = SteamNetworkingMessages();
    if (!matchmaking)
        return;
    if (!user)
        return;
    if (!messages)
        return;

    const CSteamID localId = user->GetSteamID();

    const int memberCount =
        matchmaking->GetNumLobbyMembers(g_lobbyId);

    for (int i = 0; i < memberCount; ++i)
    {
        const CSteamID member =
            matchmaking->GetLobbyMemberByIndex(g_lobbyId, i);
        if (!member.IsValid() || member == localId)
            continue;

        SteamNetworkingIdentity identity;
        identity.SetSteamID(member);
        messages->SendMessageToUser(
            identity,
            &packet,
            sizeof(packet),
            k_nSteamNetworkingSend_Reliable,
            DAMAGE_CHANNEL);
    }
}
