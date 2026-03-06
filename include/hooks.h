#pragma once

#include <cstdint>

// Pointer to the game's WorldChrManImp* global. Dereference at call time to get
// the current WorldChrManImp instance. Defined in hooks.cpp, used in damage.cpp.
extern uintptr_t* g_worldChrManPtr;

void InitHooks();
void ShutdownHooks();
