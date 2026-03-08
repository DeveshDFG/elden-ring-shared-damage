#include "damage.h"
#include "hooks.h"
#define NOMINMAX
#include <fstream>
#include "ModUtils.h"
#include <cstdint>
#include <algorithm>

// Offset reference — verify and update after each Elden Ring patch.
// WorldChrManImp playerArray:  +0x10EF8  (source: samjviana/souls_vision)
// Entry::chrIns:               +0x0000   (source: samjviana/souls_vision)
// Entry stride:                 0x0010   (8-byte ChrIns* + 8-byte pad)
// ChrIns::moduleBag:           +0x0190   (source: samjviana/souls_vision)
// ChrModuleBag::statModule:    +0x0000   (source: samjviana/souls_vision)
// ChrStatModule::hp:           +0x0138   (source: samjviana/souls_vision)
// Max co-op players:            6        (source: Seamless Co-op player cap)

static const uintptr_t PLAYER_ARRAY_OFFSET = 0x10EF8;
static const uintptr_t ENTRY_STRIDE        = 0x10;
static const int       MAX_PLAYERS         = 6;

void PropagateDamage(int damageDealt)
{
    if (!g_worldChrManPtr) return;
    uintptr_t wcm = *g_worldChrManPtr;
    if (!wcm) return;

    uintptr_t arrayBase = *reinterpret_cast<uintptr_t*>(wcm + PLAYER_ARRAY_OFFSET);
    if (!arrayBase) return;

    // Slot 0 is the local player (source of damage); propagate to slots 1..5.
    for (int i = 1; i < MAX_PLAYERS; i++)
    {
        uintptr_t chrIns = *reinterpret_cast<uintptr_t*>(arrayBase + i * ENTRY_STRIDE);
        if (!chrIns) continue;

        uintptr_t moduleBag = *reinterpret_cast<uintptr_t*>(chrIns + 0x190);
        if (!moduleBag)
        {
            char dbg[128];
            sprintf_s(dbg, "[SharedDamage] player[%d] chrIns=%p moduleBag=null\n",
                      i, reinterpret_cast<void*>(chrIns));
            OutputDebugStringA(dbg);
            ModUtils::Log("SharedDamage: player[%d] chrIns=%p moduleBag=null", i, (void*)chrIns);
            continue;
        }

        uintptr_t statModule = *reinterpret_cast<uintptr_t*>(moduleBag);
        if (!statModule)
        {
            char dbg[128];
            sprintf_s(dbg, "[SharedDamage] player[%d] chrIns=%p moduleBag=%p statModule=null\n",
                      i, reinterpret_cast<void*>(chrIns), reinterpret_cast<void*>(moduleBag));
            OutputDebugStringA(dbg);
            ModUtils::Log("SharedDamage: player[%d] chrIns=%p moduleBag=%p statModule=null",
                          i, (void*)chrIns, (void*)moduleBag);
            continue;
        }

        int32_t* hp = reinterpret_cast<int32_t*>(statModule + 0x138);
        int32_t newHp = std::max(0, *hp - damageDealt);
        {
            char dbg[192];
            sprintf_s(dbg,
                      "[SharedDamage] player[%d] chrIns=%p moduleBag=%p statModule=%p hp=%d -> %d\n",
                      i, reinterpret_cast<void*>(chrIns), reinterpret_cast<void*>(moduleBag),
                      reinterpret_cast<void*>(statModule), *hp, newHp);
            OutputDebugStringA(dbg);
        }
        ModUtils::Log("SharedDamage: player[%d] chrIns=%p moduleBag=%p statModule=%p hp=%d -> %d",
                      i, (void*)chrIns, (void*)moduleBag, (void*)statModule, *hp, newHp);
        *hp = newHp;
    }
}
