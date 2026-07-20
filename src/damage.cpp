#include "damage.h"
#include "hooks.h"
#include "shared_damage_boss_diag.h"

#include <steam/steam_api.h>

#include <algorithm>
#include <atomic>
#include <limits>

static CSteamID g_lobbyId = k_steamIDNil;
static std::atomic<int64_t> g_pendingBroadcastDamage{0};
static bool g_steamDiagStateInitialized = false;
static uint64_t g_lastDiagLocalSteamId = 0;
static uint64_t g_lastDiagLobbyId = 0;
static int g_lastDiagLobbyMemberCount = -1;

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
    {
        SharedDamageBossDiagTryLogBroadcast(
            damage, false, "nonpositive-damage", 0);
        return;
    }

    if (!IsSameWorldActive())
    {
        SharedDamageBossDiagTryLogBroadcast(
            damage, false, "same-world-inactive", 0);
        return;
    }

    const int64_t pendingTotal =
        g_pendingBroadcastDamage.fetch_add(damage, std::memory_order_release) +
        damage;
    SharedDamageBossDiagTryLogBroadcast(
        damage, true, "accepted", pendingTotal);
}

void DiscardPendingBroadcastDamage()
{
    g_pendingBroadcastDamage.store(0, std::memory_order_release);
}

void LogSharedDamageSteamStateIfChanged(uint64_t callbackInvocationCount)
{
    ISteamUser* user = SteamUser();
    if (!user)
        return;

    const uint64_t localSteamId = user->GetSteamID().ConvertToUint64();
    const bool lobbyValid = g_lobbyId.IsValid();
    const uint64_t lobbyId = lobbyValid ? g_lobbyId.ConvertToUint64() : 0;
    int lobbyMemberCount = 0;
    if (lobbyValid)
    {
        if (ISteamMatchmaking* matchmaking = SteamMatchmaking())
            lobbyMemberCount = matchmaking->GetNumLobbyMembers(g_lobbyId);
        else
            lobbyMemberCount = -1;
    }

    const bool changed =
        !g_steamDiagStateInitialized ||
        localSteamId != g_lastDiagLocalSteamId ||
        lobbyId != g_lastDiagLobbyId ||
        lobbyMemberCount != g_lastDiagLobbyMemberCount;
    if (!changed)
        return;

    g_steamDiagStateInitialized = true;
    g_lastDiagLocalSteamId = localSteamId;
    g_lastDiagLobbyId = lobbyId;
    g_lastDiagLobbyMemberCount = lobbyMemberCount;
    SharedDamageBossDiagTryLogSteamState(
        localSteamId,
        lobbyId,
        lobbyValid,
        lobbyMemberCount,
        callbackInvocationCount);
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
    const int32_t packetDamage = packet.damage;

    if (!IsSameWorldActive())
    {
        SharedDamageBossDiagTryLogFlush(
            pending,
            "discarded-same-world-inactive",
            0,
            0,
            0,
            0,
            -1,
            packetDamage);
        return;
    }

    if (!g_lobbyId.IsValid())
    {
        SharedDamageBossDiagTryLogFlush(
            pending,
            "invalid-lobby",
            0,
            0,
            0,
            0,
            -1,
            packetDamage);
        return;
    }

    ISteamMatchmaking* matchmaking = SteamMatchmaking();
    ISteamUser* user = SteamUser();
    ISteamNetworkingMessages* messages = SteamNetworkingMessages();
    if (!matchmaking)
    {
        SharedDamageBossDiagTryLogFlush(
            pending,
            "steam-matchmaking-unavailable",
            g_lobbyId.ConvertToUint64(),
            0,
            0,
            0,
            -1,
            packetDamage);
        return;
    }
    if (!user)
    {
        SharedDamageBossDiagTryLogFlush(
            pending,
            "steam-user-unavailable",
            g_lobbyId.ConvertToUint64(),
            0,
            0,
            0,
            -1,
            packetDamage);
        return;
    }
    if (!messages)
    {
        SharedDamageBossDiagTryLogFlush(
            pending,
            "steam-networking-messages-unavailable",
            g_lobbyId.ConvertToUint64(),
            0,
            0,
            0,
            -1,
            packetDamage);
        return;
    }

    const CSteamID localId = user->GetSteamID();
    SharedDamageBossDiagTryLogLocalSteamId(localId.ConvertToUint64());

    const int memberCount =
        matchmaking->GetNumLobbyMembers(g_lobbyId);
    const uint64_t lobbyId = g_lobbyId.ConvertToUint64();
    const uint64_t localSteamId = localId.ConvertToUint64();
    bool sentToAnyTarget = false;

    for (int i = 0; i < memberCount; ++i)
    {
        const CSteamID member =
            matchmaking->GetLobbyMemberByIndex(g_lobbyId, i);
        if (!member.IsValid() || member == localId)
            continue;

        sentToAnyTarget = true;
        SteamNetworkingIdentity identity;
        identity.SetSteamID(member);
        const EResult sendResult = messages->SendMessageToUser(
            identity,
            &packet,
            sizeof(packet),
            k_nSteamNetworkingSend_Reliable,
            DAMAGE_CHANNEL);
        SharedDamageBossDiagTryLogFlush(
            pending,
            sendResult == k_EResultOK ? "sent" : "send-failed",
            lobbyId,
            memberCount,
            localSteamId,
            member.ConvertToUint64(),
            static_cast<int>(sendResult),
            packetDamage);
    }

    if (!sentToAnyTarget)
    {
        SharedDamageBossDiagTryLogFlush(
            pending,
            "no-remote-targets",
            lobbyId,
            memberCount,
            localSteamId,
            0,
            -1,
            packetDamage);
    }
}
