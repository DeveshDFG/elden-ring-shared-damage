#pragma once

#include <cstdint>

enum class SharedWorldPresence : uint8_t
{
    Unavailable = 0,
    NoRemotePlayers = 1,
    RemotePlayersPresent = 2,
};

struct SharedDamageBossNetPlayersSnapshot
{
    uintptr_t worldChrMan = 0;
    uintptr_t netPlayers = 0;
    uintptr_t slots[8] = {};
    uintptr_t vtables[8] = {};
    uintptr_t moduleBags[8] = {};
    uintptr_t statModules[8] = {};
    int32_t currentHps[8] = {};
    bool currentHpReadable[8] = {};
};

struct SharedDamageWorldSnapshot
{
    SharedDamageBossNetPlayersSnapshot netPlayersSnapshot{};

    SharedWorldPresence presence = SharedWorldPresence::Unavailable;

    uintptr_t worldChrManPointerAddress = 0;
    uintptr_t localChrIns = 0;
    uintptr_t localModuleBag = 0;
    uintptr_t localStatModule = 0;

    bool worldChrManReadable = false;
    bool netPlayersReadable = false;
    // True only when production slots 0–5 were fully scanned.
    bool productionSlotsReadComplete = false;
    bool localPlayerResolved = false;
};

// Pointer to the game's WorldChrManImp* global. Dereference at call time to get
// the current WorldChrManImp instance. Defined in hooks.cpp, used in damage.cpp.
extern uintptr_t* g_worldChrManPtr;

// Function pointer to the original (unhooked) HP-write function.
// Used by PropagateDamage to apply damage to remote slots through the
// game's own write path rather than poking memory directly.
typedef void(__fastcall* DamageFunc_t)(uintptr_t rcx, int rdx);
extern DamageFunc_t fpDamageFunc;

// Apply damage to the local player by calling fpDamageFunc on the provided
// stat module. Must be called from the game thread.
void ApplyDamageToLocalPlayer(
    uintptr_t statModule,
    int32_t damage,
    int64_t pendingAmount = 0);

// Queue damage received from a remote peer for application on the game thread.
// Safe to call from any thread; drained from the Steam callback hook.
void EnqueueRemoteDamage(int32_t damage);

// True when at least one remote NetPlayers slot (1-5) is populated in-world.
bool IsSameWorldActive();

// Drain queued inbound damage using the current callback snapshot's local player.
void DrainRemoteDamage(
    uintptr_t localStatModule,
    bool localPlayerResolved,
    SharedWorldPresence presence);

void InitHooks();
void ShutdownHooks();
