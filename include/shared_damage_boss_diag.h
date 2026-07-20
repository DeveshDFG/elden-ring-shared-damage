#pragma once

#include <cstdint>

#include "damage.h"
#include "hooks.h"

inline constexpr bool kBossDiagnosticsEnabled = true;

struct SharedDamageSameWorldProbeResult
{
    SharedDamageBossNetPlayersSnapshot snapshot{};
    bool active = false;
};

struct SharedDamageWorldChrManCandidateDiag
{
    uint32_t patternMatches = 0;
    uintptr_t instructionRva = 0;
    uintptr_t pointerAddress = 0;
    uintptr_t currentValue = 0;
};

struct SharedDamageWorldChrManCandidateProbe
{
    uintptr_t pointerAddress = 0;
    SharedDamageSameWorldProbeResult probe{};
};

struct SharedDamageHookInstallDiag
{
    uintptr_t moduleBase = 0;
    SharedDamageWorldChrManCandidateDiag primaryWorldChrMan{};
    SharedDamageWorldChrManCandidateDiag fallbackWorldChrMan{};
    uintptr_t worldChrManPointerAddress = 0;
    uint32_t damagePatternMatches = 0;
    uintptr_t damagePatternMatch = 0;
    uintptr_t damageEntry = 0;
    uintptr_t damageEntryRva = 0;
    bool damagePrologueValid = false;
    uintptr_t damagePdataBeginRva = 0;
    uintptr_t damagePdataEndRva = 0;
    uint32_t hpDelta7Matches = 0;
    uintptr_t hpDelta7PatternMatch = 0;
    uintptr_t hpDelta7Entry = 0;
    uintptr_t hpDelta7EntryRva = 0;
    bool hpDelta7PrologueValid = false;
    uintptr_t hpDelta7PdataBeginRva = 0;
    uintptr_t hpDelta7PdataEndRva = 0;
    uint32_t hpDelta8Matches = 0;
    uintptr_t hpDelta8Entry = 0;
    uintptr_t hpDelta8EntryRva = 0;
    bool hpDelta8PrologueValid = false;
    uintptr_t hpDelta8PdataBeginRva = 0;
    uintptr_t hpDelta8PdataEndRva = 0;
    int mhInitializeResult = -1;
    int hpWriteCreateResult = -1;
    int hpDelta7CreateResult = -1;
    int hpDelta8CreateResult = -1;
    int callbacksCreateResult = -1;
    int enableResult = -1;
    int mhDisableResult = -1;
    const char* failedStage = nullptr;
};

void InitSharedDamageBossDiag();
void ShutdownSharedDamageBossDiag();

uint64_t SharedDamageBossDiagNotifyCallbackInvocation();

void SharedDamageBossDiagLogStartup(
    bool hpWriteHookEnabled,
    bool hpDelta7HookEnabled,
    bool hpDelta8HookEnabled,
    bool callbacksHookEnabled,
    bool sharingReady,
    const SharedDamageBossNetPlayersSnapshot& snapshot,
    const SharedDamageHookInstallDiag& installDiag);

void SharedDamageBossDiagLogSameWorldTransition(
    bool activeBefore,
    bool activeAfter,
    const SharedDamageBossNetPlayersSnapshot& snapshot);

bool SharedDamageBossDiagTryLogWorldProbe(
    uintptr_t productionPointerAddress,
    const SharedDamageSameWorldProbeResult& productionProbe,
    const SharedDamageWorldChrManCandidateProbe& primary,
    const SharedDamageWorldChrManCandidateProbe& fallback,
    bool candidatesAlias,
    uintptr_t resolvedLocalStatModule,
    int matchingSlot,
    uint64_t callbackInvocationCount);

bool SharedDamageBossDiagTryLogDelta7Entry(
    uintptr_t statModule,
    uintptr_t cachedLocalStatModule,
    int32_t deltaHp,
    bool modulesMatch,
    uintptr_t callerRva,
    bool captureRan,
    uint32_t captureSeq);

bool SharedDamageBossDiagTryLogDelta8Entry(
    uintptr_t statModule,
    uintptr_t cachedLocalStatModule,
    int32_t deltaHp,
    bool modulesMatch,
    uintptr_t callerRva,
    bool captureRan,
    uint32_t captureSeq);

bool SharedDamageBossDiagTryLogSteamState(
    uint64_t localSteamId,
    uint64_t lobbyId,
    bool lobbyValid,
    int lobbyMemberCount,
    uint64_t callbackInvocationCount);

bool SharedDamageBossDiagCanLogHpDecrease();

bool SharedDamageBossDiagTryLogDeltaLocal(
    uint32_t captureSeq,
    uintptr_t statModule,
    uintptr_t cachedLocalStatModule,
    int32_t deltaHp,
    uintptr_t callerRva,
    const char* sourceWrapper,
    bool captureRan);

bool SharedDamageBossDiagTryLogDeltaNonLocal(
    uintptr_t statModule,
    uintptr_t cachedLocalStatModule,
    int32_t deltaHp,
    uintptr_t callerRva);

bool SharedDamageBossDiagTryLogHpDecrease(
    uintptr_t statModule,
    uintptr_t cachedLocalStatModule,
    uintptr_t resolvedLocalStatModule,
    int matchingNetPlayerSlot,
    uintptr_t callerRva,
    int32_t currentHp,
    int32_t newHp,
    bool hasRawDamage,
    int32_t rawDamage,
    uint32_t pendingSeq,
    uint64_t pendingAgeMs,
    const char* consumeResult,
    const char* pendingSource,
    const char* decision);

bool SharedDamageBossDiagTryLogBroadcast(
    int32_t damage,
    bool accepted,
    const char* reason,
    int64_t pendingTotalAfter);

bool SharedDamageBossDiagTryLogFlush(
    int64_t pendingAmount,
    const char* outcome,
    uint64_t lobbyId,
    int lobbyMemberCount,
    uint64_t localSteamId,
    uint64_t targetSteamId,
    int sendResult,
    int32_t packetDamage);

bool SharedDamageBossDiagTryLogLocalSteamId(uint64_t localSteamId);

bool SharedDamageBossDiagTryLogReceive(
    int messageSize,
    uint64_t senderSteamId,
    bool valid,
    const char* reason,
    int32_t damage);

bool SharedDamageBossDiagTryLogEnqueue(
    int32_t damage,
    bool accepted,
    const char* reason,
    int64_t pendingRemoteTotal);

bool SharedDamageBossDiagTryLogDrainApply(
    int64_t pendingAmount,
    bool applied,
    const char* reason,
    int32_t requestedDamage,
    int32_t currentHp,
    int32_t newHp);

bool SharedDamageBossDiagTryLogUnifiedWorldSnapshot(
    uint32_t snapshotSeq,
    uint64_t callbackInvocationCount,
    const SharedDamageWorldSnapshot& snapshot,
    bool latchedBefore,
    bool latchedAfter,
    SharedDamageLobbyPresence lobbyPresence,
    const char* transitionReason,
    bool queuesCleared,
    const char* snapshotSource);
