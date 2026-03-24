#include "param_patch.h"

#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <fstream>

#include <coresystem/cs_param.hpp>
#include <param/param.hpp>

#include "ModUtils.h"

namespace
{
constexpr int32_t SOURCE_SPEFFECT_ID  = 29521;
constexpr int32_t RUNTIME_SPEFFECT_ID = 90061;

constexpr int PARAM_WAIT_TIMEOUT_MS = 120000;

constexpr size_t SPEFFECT_LIFECYCLE_FLAGS_OFFSET = 0x352;
constexpr uint8_t DESTINED_DEATH_HP_MULT_MASK = 0x10;
constexpr uint8_t HP_BURN_EFFECT_MASK = 0x20;

static void SetBit(uint8_t& value, uint8_t mask, bool enabled)
{
    if (enabled)
        value |= mask;
    else
        value &= static_cast<uint8_t>(~mask);
}

static void ApplyRuntimeSpEffectOverrides(from::paramdef::SP_EFFECT_PARAM_ST& effect)
{
    effect.iconId = 20460;
    effect.effectEndurance = -1.0f;
    effect.maxHpRate = 0.980f;
    effect.spCategory = 10;
    effect.spAttribute = 0;
    effect.wepParamChange = 3;
    effect.disableMadness = false;
    effect.vfxId = 9014;
    effect.effectTargetOpposeTarget = true;
    effect.effectTargetSelfTarget = false;
    effect.eraseOnBonfireRecover = true;
    effect.isContractSpEffectLife = true;
    effect.isIgnoreNoDamage = true;
    effect.spAttributeVariationValue = 1;
}

static void ApplyRemainingSpEffectBits(from::paramdef::SP_EFFECT_PARAM_ST& effect)
{
    auto* raw = reinterpret_cast<uint8_t*>(&effect);
    SetBit(*(raw + SPEFFECT_LIFECYCLE_FLAGS_OFFSET), DESTINED_DEATH_HP_MULT_MASK, true);
    SetBit(*(raw + SPEFFECT_LIFECYCLE_FLAGS_OFFSET), HP_BURN_EFFECT_MASK, true);
}

static bool PatchSpEffectRow()
{
    auto [dstRow, dstExists] = from::param::SpEffectParam[RUNTIME_SPEFFECT_ID];
    if (!dstExists)
    {
        ModUtils::Log("SharedDamage: SpEffectParam row 90061 not found");
        return false;
    }

    auto [srcRow, srcExists] = from::param::SpEffectParam[SOURCE_SPEFFECT_ID];
    if (srcExists)
    {
        dstRow = srcRow;
        ModUtils::Log("SharedDamage: SpEffectParam[90061] cloned from source row 29521 before overrides");
    }
    else
    {
        dstRow = from::paramdef::SP_EFFECT_PARAM_ST{};
        ModUtils::Log("SharedDamage: SpEffectParam source row 29521 not found; using libER defaults");
    }

    ApplyRuntimeSpEffectOverrides(dstRow);
    ApplyRemainingSpEffectBits(dstRow);

    {
        char dbg[512];
        auto* raw = reinterpret_cast<const uint8_t*>(&dstRow);
        sprintf_s(
            dbg,
            "[SharedDamage] SpEffect[90061] final: iconId=%d effectEndurance=%.3f maxHpRate=%.3f spCategory=%u spAttribute=%u wepParamChange=%u vfxId=%d oppose=%d self=%d eraseOnBonfire=%d contract=%d ignoreNoDamage=%d spAttrVar=%u lifecycle=0x%02X\n",
            dstRow.iconId,
            dstRow.effectEndurance,
            dstRow.maxHpRate,
            static_cast<unsigned>(dstRow.spCategory),
            static_cast<unsigned>(dstRow.spAttribute),
            static_cast<unsigned>(dstRow.wepParamChange),
            dstRow.vfxId,
            dstRow.effectTargetOpposeTarget ? 1 : 0,
            dstRow.effectTargetSelfTarget ? 1 : 0,
            dstRow.eraseOnBonfireRecover ? 1 : 0,
            dstRow.isContractSpEffectLife ? 1 : 0,
            dstRow.isIgnoreNoDamage ? 1 : 0,
            static_cast<unsigned>(dstRow.spAttributeVariationValue),
            static_cast<unsigned>(raw[SPEFFECT_LIFECYCLE_FLAGS_OFFSET]));
        OutputDebugStringA(dbg);
    }

    OutputDebugStringA("[SharedDamage] SpEffectParam[90061] patched successfully via libER\n");
    ModUtils::Log("SharedDamage: SpEffectParam[90061] patched successfully via libER");
    return true;
}

static bool PatchAtkParamNpc()
{
    uint32_t totalRows = 0;
    uint32_t changedRows = 0;

    for (auto [rowId, row] : from::param::AtkParam_Npc)
    {
        ++totalRows;
        if (row.spEffectId3 == RUNTIME_SPEFFECT_ID)
            continue;

        row.spEffectId3 = RUNTIME_SPEFFECT_ID;
        ++changedRows;
        (void)rowId;
    }

    char dbg[192];
    sprintf_s(dbg, "[SharedDamage] AtkParam_Npc patched via libER: totalRows=%u changedRows=%u\n",
              totalRows, changedRows);
    OutputDebugStringA(dbg);
    ModUtils::Log("SharedDamage: AtkParam_Npc patched via libER: totalRows=", totalRows,
                  " changedRows=", changedRows);
    return totalRows != 0;
}
}

void InitRuntimeParamPatch()
{
    OutputDebugStringA("[SharedDamage] InitRuntimeParamPatch entered\n");
    ModUtils::Log("SharedDamage: InitRuntimeParamPatch entered");

    OutputDebugStringA("[SharedDamage] Waiting for libER param repository\n");
    ModUtils::Log("SharedDamage: Waiting for libER param repository");

    if (!from::CS::SoloParamRepository::wait_for_params(PARAM_WAIT_TIMEOUT_MS))
    {
        OutputDebugStringA("[SharedDamage] Timed out waiting for libER param repository\n");
        ModUtils::Log("SharedDamage: Timed out waiting for libER param repository");
        return;
    }

    auto repository = from::CS::SoloParamRepository::instance();
    if (!repository)
    {
        OutputDebugStringA("[SharedDamage] libER param repository instance unavailable after wait\n");
        ModUtils::Log("SharedDamage: libER param repository instance unavailable after wait");
        return;
    }

    {
        char dbg[160];
        sprintf_s(dbg, "[SharedDamage] libER param repository ready at %p\n",
                  reinterpret_cast<void*>(&repository.reference()));
        OutputDebugStringA(dbg);
        ModUtils::Log("SharedDamage: libER param repository ready at ", (void*)&repository.reference());
    }

    const bool spPatched = PatchSpEffectRow();
    const bool atkPatched = PatchAtkParamNpc();
    if (!spPatched || !atkPatched)
    {
        OutputDebugStringA("[SharedDamage] Runtime param patch incomplete\n");
        ModUtils::Log("SharedDamage: Runtime param patch incomplete (spEffectPatched=", spPatched ? 1 : 0,
                      ", atkPatched=", atkPatched ? 1 : 0, ")");
        return;
    }

    OutputDebugStringA("[SharedDamage] Runtime param patch complete via libER\n");
    ModUtils::Log("SharedDamage: Runtime param patch complete via libER");
}
