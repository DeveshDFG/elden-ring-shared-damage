#include "param_patch.h"
#include "bullet_sp_effect_allowlist_generated.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include <coresystem/cs_param.hpp>
#include <param/param.hpp>

using namespace std;

namespace
{
constexpr int32_t SOURCE_SPEFFECT_ID = 29521;
constexpr int32_t RUNTIME_SPEFFECT_ID = 90061;
constexpr int32_t PERFECT_DEFLECT_MARKER_ID = 102001;
constexpr int PARAM_WAIT_TIMEOUT_MS = 120000;

constexpr size_t SPEFFECT_LIFECYCLE_FLAGS_OFFSET = 0x352;
constexpr uint8_t DESTINED_DEATH_HP_MULT_MASK = 0x10;
constexpr uint8_t HP_BURN_EFFECT_MASK = 0x20;

constexpr array<int32_t, 35> EXCLUDED_ATK_PARAM_NPC_IDS = {
    280000,
    280001,
    2110260,
    2110270,
    2110340,
    2110341,
    2110350,
    2110351,
    2110370,
    2110400,
    2110401,
    2110402,
    2110403,
    2110420,
    2110421,
    2110460,
    2110701,
    2110720,
    2110730,
    2110731,
    2110740,
    2110741,
    2110742,
    2110743,
    2110750,
    2110751,
    8000000,
    8000001,
    8000002,
    8000003,
    8000004,
    8000010,
    8000011,
    8000015,
    8000030,
};

static bool IsExcludedAtkParamNpcRow(int32_t rowId)
{
    return binary_search(
        EXCLUDED_ATK_PARAM_NPC_IDS.begin(),
        EXCLUDED_ATK_PARAM_NPC_IDS.end(),
        rowId);
}

static void SetBit(uint8_t& value, uint8_t mask, bool enabled)
{
    if (enabled)
        value |= mask;
    else
        value &= static_cast<uint8_t>(~mask);
}

static void ApplyRuntimeSpEffectOverrides(
    from::paramdef::SP_EFFECT_PARAM_ST& effect)
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
    effect.isIgnoreNoDamage = false;
    effect.spAttributeVariationValue = 1;
}

static void ApplyRemainingSpEffectBits(
    from::paramdef::SP_EFFECT_PARAM_ST& effect)
{
    auto* raw = reinterpret_cast<uint8_t*>(&effect);
    SetBit(
        raw[SPEFFECT_LIFECYCLE_FLAGS_OFFSET],
        DESTINED_DEATH_HP_MULT_MASK,
        true);
    SetBit(
        raw[SPEFFECT_LIFECYCLE_FLAGS_OFFSET],
        HP_BURN_EFFECT_MASK,
        true);
}

static bool PatchSpEffectRow()
{
    auto [destination, destinationExists] =
        from::param::SpEffectParam[RUNTIME_SPEFFECT_ID];
    if (!destinationExists)
        return false;

    auto [source, sourceExists] =
        from::param::SpEffectParam[SOURCE_SPEFFECT_ID];
    if (!sourceExists)
        return false;

    auto [marker, markerExists] =
        from::param::SpEffectParam[PERFECT_DEFLECT_MARKER_ID];
    (void)marker;
    if (!markerExists)
        return false;

    destination = source;
    ApplyRuntimeSpEffectOverrides(destination);
    ApplyRemainingSpEffectBits(destination);
    return true;
}

static bool PatchAtkParamNpc()
{
    uint32_t total = 0;
    for (auto [rowId, row] : from::param::AtkParam_Npc)
    {
        ++total;
        if (IsExcludedAtkParamNpcRow(rowId))
            continue;
        row.spEffectId3 = RUNTIME_SPEFFECT_ID;
    }
    return total != 0;
}

static bool AtkParamNpcHasHpDamagePotential(
    const from::paramdef::ATK_PARAM_ST& attack)
{
    return attack.atkPhys > 0 ||
           attack.atkMag > 0 ||
           attack.atkFire > 0 ||
           attack.atkThun > 0 ||
           attack.atkDark > 0 ||
           attack.atkPhysCorrection > 0 ||
           attack.atkMagCorrection > 0 ||
           attack.atkFireCorrection > 0 ||
           attack.atkThunCorrection > 0 ||
           attack.atkDarkCorrection > 0;
}

static bool BulletRowHasDamagingAttack(
    const from::paramdef::BULLET_PARAM_ST& bullet)
{
    if (bullet.atkId_Bullet <= 0)
        return false;

    auto [attack, attackExists] =
        from::param::AtkParam_Npc[bullet.atkId_Bullet];
    if (!attackExists)
        return false;

    return AtkParamNpcHasHpDamagePotential(attack);
}

static bool PatchBulletAllowlist()
{
    if (kDestinedDeathBulletAllowlistCount != 6119)
        return false;

    uint32_t patchedRows = 0;
    for (size_t i = 0; i < kDestinedDeathBulletAllowlistCount; ++i)
    {
        auto [row, exists] =
            from::param::Bullet[kDestinedDeathBulletAllowlist[i]];
        if (!exists || !BulletRowHasDamagingAttack(row))
            continue;
        row.spEffectId3 = RUNTIME_SPEFFECT_ID;
        ++patchedRows;
    }
    return patchedRows != 0;
}
}

bool InitDestinedDeathParamPatch()
{
    if (!from::CS::SoloParamRepository::wait_for_params(PARAM_WAIT_TIMEOUT_MS))
        return false;

    const auto repository = from::CS::SoloParamRepository::instance();
    if (!repository)
        return false;

    if (!PatchSpEffectRow())
        return false;

    if (!PatchBulletAllowlist())
        return false;

    return PatchAtkParamNpc();
}
