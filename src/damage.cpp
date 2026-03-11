#include "damage.h"
#include "hooks.h"
#define NOMINMAX
#include <fstream>
#include "ModUtils.h"
#include <cstdint>
#include <algorithm>
#include <steam/steam_api.h>

// Offset reference — verify and update after each Elden Ring patch.
// WorldChrManImp playerArray:  +0x10EF8  (source: samjviana/souls_vision)
// Entry::chrIns:               +0x0000   (source: samjviana/souls_vision)
// Entry stride:                 0x0010   (8-byte ChrIns* + 8-byte pad)
// ChrIns::moduleBag:           +0x0190   (source: samjviana/souls_vision)
// ChrModuleBag::statModule:    +0x0000   (source: samjviana/souls_vision)
// ChrStatModule::hp:           +0x0138   (source: samjviana/souls_vision)
// Max co-op players:            6        (source: Seamless Co-op player cap)

// --- Lobby tracking via Steam callback ---
//
// Seamless Co-op uses ISteamMatchmaking CreateLobby/JoinLobby for session
// rendezvous. We capture the lobby ID from LobbyEnter_t so BroadcastDamage
// can enumerate all connected peers via GetLobbyMemberByIndex and send to
// each one, skipping the local player. No slot-index mapping needed.
//
// SteamAPI_RunCallbacks() is called by the game (or ersc.dll) on the main
// thread; our callback is registered into the same Steam client context and
// will be dispatched automatically — provided our DLL loads after SteamAPI_Init,
// which is guaranteed when launched via me3. Watch for the OnLobbyEnter log
// on first session join to confirm the callback is firing correctly.
static CSteamID g_lobbyId = k_steamIDNil;

class LobbyTracker
{
public:
    STEAM_CALLBACK(LobbyTracker, OnLobbyEnter, LobbyEnter_t);
    STEAM_CALLBACK(LobbyTracker, OnLobbyChatUpdate, LobbyChatUpdate_t);
    STEAM_CALLBACK(LobbyTracker, OnSessionRequest, SteamNetworkingMessagesSessionRequest_t);
    STEAM_CALLBACK(LobbyTracker, OnSessionFailed, SteamNetworkingMessagesSessionFailed_t);
};

void LobbyTracker::OnLobbyEnter(LobbyEnter_t* p)
{
    if (p->m_EChatRoomEnterResponse != k_EChatRoomEnterResponseSuccess)
    {
        char dbg[128];
        sprintf_s(dbg,
                  "[SharedDamage] LobbyEnter: rejected (response=%u)\n",
                  p->m_EChatRoomEnterResponse);
        OutputDebugStringA(dbg);
        ModUtils::Log("SharedDamage: LobbyEnter: rejected (response=%u)",
                      p->m_EChatRoomEnterResponse);
        return;
    }
    g_lobbyId = CSteamID(p->m_ulSteamIDLobby);
    const int memberCount = SteamMatchmaking()
                          ? SteamMatchmaking()->GetNumLobbyMembers(g_lobbyId) : -1;
    char dbg[192];
    sprintf_s(dbg,
              "[SharedDamage] *** LobbyEnter callback FIRED *** lobby=%llu members=%d\n",
              g_lobbyId.ConvertToUint64(), memberCount);
    OutputDebugStringA(dbg);
    ModUtils::Log("SharedDamage: *** LobbyEnter callback FIRED *** lobby=%I64u members=%d",
                  g_lobbyId.ConvertToUint64(), memberCount);
}

void LobbyTracker::OnLobbyChatUpdate(LobbyChatUpdate_t* p)
{
    // Clear g_lobbyId when the local user leaves or is kicked.
    if (!SteamUser()) return;
    const bool localUserChanged =
        (CSteamID(p->m_ulSteamIDUserChanged) == SteamUser()->GetSteamID());
    const bool leftOrDisconnected =
        (p->m_rgfChatMemberStateChange & (k_EChatMemberStateChangeLeft |
                                          k_EChatMemberStateChangeDisconnected |
                                          k_EChatMemberStateChangeKicked));
    if (localUserChanged && leftOrDisconnected)
    {
        OutputDebugStringA("[SharedDamage] LobbyChatUpdate: local user left — clearing lobby ID\n");
        ModUtils::Log("SharedDamage: LobbyChatUpdate: local user left — clearing lobby ID");
        g_lobbyId = k_steamIDNil;
    }
}

void LobbyTracker::OnSessionRequest(SteamNetworkingMessagesSessionRequest_t* p)
{
    if (SteamNetworkingMessages())
        SteamNetworkingMessages()->AcceptSessionWithUser(p->m_identityRemote);
    char dbg[128];
    sprintf_s(dbg, "[SharedDamage] AcceptSessionWithUser: %llu\n",
              p->m_identityRemote.GetSteamID64());
    OutputDebugStringA(dbg);
    ModUtils::Log("SharedDamage: AcceptSessionWithUser: %I64u",
                  p->m_identityRemote.GetSteamID64());
}

void LobbyTracker::OnSessionFailed(SteamNetworkingMessagesSessionFailed_t* p)
{
    char dbg[192];
    sprintf_s(dbg, "[SharedDamage] SteamNetworkingMessagesSessionFailed: peer=%llu\n",
              p->m_info.m_identityRemote.GetSteamID64());
    OutputDebugStringA(dbg);
    ModUtils::Log("SharedDamage: SteamNetworkingMessagesSessionFailed: peer=%I64u",
                  p->m_info.m_identityRemote.GetSteamID64());
}

// Constructed at DLL load time (after SteamAPI_Init in the host EXE).
// STEAM_CALLBACK registers into the live Steam client context automatically.
static LobbyTracker g_lobbyTracker;

void BroadcastDamage(int32_t damage)
{
    ISteamMatchmaking*        mm   = SteamMatchmaking();
    ISteamUser*               su   = SteamUser();
    ISteamNetworkingMessages* msgs = SteamNetworkingMessages();
    if (!mm || !su || !msgs || !g_lobbyId.IsValid()) return;

    const DamagePacket pkt{ DAMAGE_PACKET_MAGIC, damage };
    const CSteamID     localId = su->GetSteamID();
    const int          count   = mm->GetNumLobbyMembers(g_lobbyId);

    for (int i = 0; i < count; i++)
    {
        const CSteamID member = mm->GetLobbyMemberByIndex(g_lobbyId, i);
        if (member == localId) continue;

        SteamNetworkingIdentity identity;
        identity.SetSteamID(member);
        const EResult result = msgs->SendMessageToUser(
            identity, &pkt, sizeof(pkt), k_nSteamNetworkingSend_Reliable, DAMAGE_CHANNEL);

        char dbg[192];
        sprintf_s(dbg,
                  "[SharedDamage] BroadcastDamage: peer=%llu damage=%d result=%d\n",
                  member.ConvertToUint64(), damage, (int)result);
        OutputDebugStringA(dbg);
        ModUtils::Log("SharedDamage: BroadcastDamage: peer=%I64u damage=%d result=%d",
                      member.ConvertToUint64(), damage, (int)result);
    }
}
