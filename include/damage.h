#pragma once

#include <cstdint>

// P2P packet layout for damage propagation.
// Sent on DAMAGE_CHANNEL by the machine that took damage;
// received and self-applied on every peer.
static constexpr uint32_t DAMAGE_PACKET_MAGIC = 0x53444D47; // 'SDMG'
static constexpr int      DAMAGE_CHANNEL      = 32767;      // high value to avoid conflict with ersc ISteamNetworking channels

#pragma pack(push, 1)
struct DamagePacket
{
    uint32_t magic;
    int32_t  damage;
};
#pragma pack(pop)

// Broadcast a damage event to all connected peers via Steam P2P.
// Called by hkDamageFunc after the local HP write is confirmed.
void BroadcastDamage(int32_t damage);

// Sends the accumulated local damage as one packet. Called from the
// Steam callback hook once per callback cycle.
void FlushBroadcastDamage();

// Clears queued outbound damage without sending.
void DiscardPendingBroadcastDamage();

enum class SharedDamageLobbyPresence : uint8_t
{
    Unknown = 0,
    NoRemoteMembers = 1,
    RemoteMembersPresent = 2,
};

SharedDamageLobbyPresence GetSharedDamageLobbyPresence();

// Diagnostic-only Steam identity/lobby snapshot. Does not mutate lobby state.
void LogSharedDamageSteamStateIfChanged(uint64_t callbackInvocationCount);
