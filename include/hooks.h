#pragma once

#include <cstdint>

// Pointer to the game's WorldChrManImp* global. Dereference at call time to get
// the current WorldChrManImp instance. Defined in hooks.cpp, used in damage.cpp.
extern uintptr_t* g_worldChrManPtr;

// Function pointer to the original (unhooked) HP-write function.
// Used by PropagateDamage to apply damage to remote slots through the
// game's own write path rather than poking memory directly.
typedef void(__fastcall* DamageFunc_t)(uintptr_t rcx, int rdx);
extern DamageFunc_t fpDamageFunc;

// Apply damage to the local player by calling fpDamageFunc on slot 0.
// Must be called from the game thread (i.e. from within DrainRemoteDamage).
void ApplyDamageToLocalPlayer(int32_t damage);

// Apply the shared on-hit SpEffect to the local player.
// Must be called on the same game thread as ApplyDamageToLocalPlayer.
void ApplySharedHitSpEffectToLocalPlayer();

// Queue damage received from a remote peer for application on the game thread.
// Safe to call from any thread; drained inside hkDamageFunc.
void EnqueueRemoteDamage(int32_t damage);

void InitHooks();
void ShutdownHooks();
