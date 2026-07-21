#pragma once

#include <cstdint>

// Queue damage received from a remote peer for application on the game thread.
// Safe to call from any thread; drained from the Steam callback hook.
void EnqueueRemoteDamage(int32_t damage);

// True when at least one remote NetPlayers slot (1-5) is populated in-world.
bool IsSameWorldActive();

void InitHooks();
void ShutdownHooks();
