#define NOMINMAX
#include "hooks.h"
#include "damage.h"
#include "shared_damage_boss_diag.h"

#include <windows.h>
#include <psapi.h>
#include <MinHook.h>
#include <steam/steam_api.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <intrin.h>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

namespace
{
constexpr const char* WORLD_CHR_MAN_PATTERN =
    "48 8b 05 ? ? ? ? 48 85 c0 74 0f 48 39 88 ? ? ? ? 75 06 89 b1 5c 03 00 00 0f 28 05 ? ? ? ? 4c 8d 45 e7";
constexpr const char* WORLD_CHR_MAN_PATTERN_FALLBACK =
    "48 8b 35 ? ? ? ? 48 85 f6 ? ? bb 01 00 00 00 89 5c 24 20 48 8b b6";
constexpr const char* DAMAGE_FUNC_PROLOGUE =
    "48 89 5c 24 18 48 89 6c 24 20 89 54 24 10 56 57 41 56 48 83 ec 30";
constexpr const char* HP_DELTA7_WRAPPER_PATTERN =
    "03 9f 38 01 00 00 85 db 7f ? 48 8b cf e8 ? ? ? ? 84 c0 74 ? "
    "bb 01 00 00 00 0f b6 44 24 70 44 0f b6 c6 f3 0f 10 44 24 68 "
    "8b d3 f3 0f 10 5c 24 60 48 8b cf";
constexpr const char* HP_DELTA8_WRAPPER_PATTERN =
    "48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 "
    "48 83 ec 30 41 0f b6 f1 41 0f b6 e8 8b da 48 8b f9 "
    "85 d2 79 1e e8 ? ? ? ? 44 0f b6 c6 40 0f b6 d5";
constexpr uintptr_t HP_DELTA7_WRAPPER_BACKTRACK = 0x42;
constexpr uintptr_t HP_WRITE_EXPECTED_RVA = 0x436EF0;
constexpr uintptr_t HP_DELTA7_EXPECTED_RVA = 0x4364F0;
constexpr uintptr_t HP_DELTA8_EXPECTED_RVA = 0x436590;
constexpr uintptr_t WORLD_CHR_MAN_NET_PLAYERS_OFFSET = 0x10EF8;
constexpr uintptr_t NET_PLAYERS_SLOT_STRIDE = 0x10;
constexpr int NET_PLAYERS_LOCAL_SLOT = 0;
constexpr int NET_PLAYERS_REMOTE_SLOT_FIRST = 1;
constexpr int NET_PLAYERS_REMOTE_SLOT_LAST = 5;
constexpr int NET_PLAYERS_PRODUCTION_SLOT_LAST = 5;
constexpr int NET_PLAYERS_DIAGNOSTIC_SLOT_LAST = 7;
constexpr uintptr_t kMinValidUserPointer = 0x10000;

using HpDelta7_t = void(__fastcall*)(
    uintptr_t statModule, int32_t deltaHp, uint8_t flagA, uint8_t flagB,
    float arg5, float arg6, uint8_t flagC);
using HpDelta8_t = void(__fastcall*)(
    uintptr_t statModule, int32_t deltaHp, uint8_t flagA, uint8_t flagB,
    uint8_t flagC, float arg6, float arg7, uint8_t flagD);
using RunCallbacks_t = void(*)();

HpDelta7_t fpHpDelta7 = nullptr;
HpDelta8_t fpHpDelta8 = nullptr;
RunCallbacks_t fpRunCallbacks = nullptr;
atomic<uintptr_t> g_cachedLocalStatModule{0};
atomic<int64_t> g_damagePendingTotal{0};
atomic<bool> g_runCallbacksHookInstalled{false};
atomic<bool> g_sameWorldActive{false};
atomic<ULONGLONG> g_nextWorldProbeTickMs{0};
uint64_t g_worldProbeSampleCount = 0;
bool g_havePreviousWorldProbe = false;
SharedDamageSameWorldProbeResult g_previousWorldProbe{};

uintptr_t g_diagPrimaryWorldChrManPtrAddr = 0;
uintptr_t g_diagFallbackWorldChrManPtrAddr = 0;

enum class PendingDamageSource : uint8_t
{
    None = 0,
    HpDelta7 = 1,
    HpDelta8 = 2,
};

struct PendingDamageContext
{
    uintptr_t statModule = 0;
    int32_t rawDamage = 0;
    ULONGLONG tickMs = 0;
    bool active = false;
    uint32_t captureSeq = 0;
    PendingDamageSource sourceWrapper = PendingDamageSource::None;
};

struct BossPendingConsumeDiag
{
    uint32_t pendingSeq = 0;
    uint64_t pendingAgeMs = 0;
    const char* result = "no-pending";
    PendingDamageSource pendingSource = PendingDamageSource::None;
};

thread_local PendingDamageContext g_pendingDamage;
constexpr ULONGLONG PENDING_DAMAGE_TTL_MS = 250;
atomic<uint32_t> g_nextCaptureSeq{1};
SharedDamageWorldSnapshot g_lastProductionSnapshot{};
atomic<uint32_t> g_nextSnapshotSeq{0};

static uintptr_t GetGameModuleBase()
{
    HMODULE module = GetModuleHandleA("eldenring.exe");
    if (!module)
        module = GetModuleHandleA(nullptr);
    return reinterpret_cast<uintptr_t>(module);
}

static uintptr_t ScanPattern(const char* pattern, uintptr_t startFrom = 0)
{
    vector<string> tokens;
    istringstream stream(pattern);
    for (string token; stream >> token;)
        tokens.push_back(token);
    if (tokens.empty())
        return 0;

    const uintptr_t moduleBase = GetGameModuleBase();
    if (!moduleBase)
        return 0;

    MODULEINFO moduleInfo{};
    if (!GetModuleInformation(
            GetCurrentProcess(), reinterpret_cast<HMODULE>(moduleBase),
            &moduleInfo, sizeof(moduleInfo)))
        return 0;

    const uintptr_t scanEnd = moduleBase + moduleInfo.SizeOfImage;
    uintptr_t regionAddress = max(moduleBase, startFrom);
    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQuery(
               reinterpret_cast<void*>(regionAddress), &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        if (regionBase >= scanEnd)
            break;

        const DWORD protection = mbi.Protect & 0xff;
        const bool readable =
            mbi.State == MEM_COMMIT &&
            (protection == PAGE_READONLY ||
             protection == PAGE_READWRITE ||
             protection == PAGE_WRITECOPY ||
             protection == PAGE_EXECUTE_READ ||
             protection == PAGE_EXECUTE_READWRITE ||
             protection == PAGE_EXECUTE_WRITECOPY);

        if (readable)
        {
            const uintptr_t regionEnd = min(regionBase + mbi.RegionSize, scanEnd);
            const uintptr_t scanStart = max(regionBase, startFrom);
            for (uintptr_t current = scanStart;
                 current + tokens.size() <= regionEnd;
                 ++current)
            {
                bool matches = true;
                for (size_t i = 0; i < tokens.size(); ++i)
                {
                    if (tokens[i] == "?")
                        continue;
                    const auto expected =
                        static_cast<uint8_t>(stoul(tokens[i], nullptr, 16));
                    if (*reinterpret_cast<const uint8_t*>(current + i) != expected)
                    {
                        matches = false;
                        break;
                    }
                }
                if (matches)
                    return current;
            }
        }

        const uintptr_t next = regionBase + mbi.RegionSize;
        if (next <= regionAddress)
            break;
        regionAddress = next;
    }

    return 0;
}

static uintptr_t ScanUniquePattern(const char* pattern)
{
    const uintptr_t first = ScanPattern(pattern);
    if (!first)
        return 0;
    return ScanPattern(pattern, first + 1) ? 0 : first;
}

static uint32_t CountPatternMatches(const char* pattern)
{
    uint32_t count = 0;
    uintptr_t searchFrom = 0;
    while (true)
    {
        const uintptr_t match = ScanPattern(pattern, searchFrom);
        if (!match)
            break;
        ++count;
        searchFrom = match + 1;
    }
    return count;
}

static uintptr_t ResolveRipRelative(uintptr_t displacementAddress)
{
    const int32_t displacement =
        *reinterpret_cast<const int32_t*>(displacementAddress);
    return displacementAddress + sizeof(displacement) + displacement;
}

static uintptr_t ToRva(uintptr_t address)
{
    const uintptr_t moduleBase = GetGameModuleBase();
    return moduleBase && address >= moduleBase ? address - moduleBase : 0;
}

static bool LookupPdataRange(
    uintptr_t address, uintptr_t& begin, uintptr_t& end)
{
    DWORD64 imageBase = 0;
    RUNTIME_FUNCTION* runtimeFunction =
        RtlLookupFunctionEntry(address, &imageBase, nullptr);
    if (!runtimeFunction)
        return false;
    begin = imageBase + runtimeFunction->BeginAddress;
    end = imageBase + runtimeFunction->EndAddress;
    return true;
}

static bool ValidateFunctionEntry(
    uintptr_t entry,
    uintptr_t expectedEntryRva,
    uintptr_t& pdataBeginRva,
    uintptr_t& pdataEndRva)
{
    pdataBeginRva = 0;
    pdataEndRva = 0;
    if (!entry)
        return false;

    const uintptr_t moduleBase = GetGameModuleBase();
    if (!moduleBase)
        return false;

    uintptr_t pdataBegin = 0;
    uintptr_t pdataEnd = 0;
    if (!LookupPdataRange(entry, pdataBegin, pdataEnd))
        return false;

    pdataBeginRva = ToRva(pdataBegin);
    pdataEndRva = ToRva(pdataEnd);
    return pdataBeginRva == expectedEntryRva;
}

static SharedDamageWorldChrManCandidateDiag ResolveWorldChrManCandidate(
    const char* pattern)
{
    SharedDamageWorldChrManCandidateDiag candidate{};
    candidate.patternMatches = CountPatternMatches(pattern);
    if (candidate.patternMatches != 1)
        return candidate;

    const uintptr_t instruction = ScanUniquePattern(pattern);
    if (!instruction)
        return candidate;

    candidate.instructionRva = ToRva(instruction);
    candidate.pointerAddress = ResolveRipRelative(instruction + 3);
    __try
    {
        candidate.currentValue =
            *reinterpret_cast<uintptr_t*>(candidate.pointerAddress);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        candidate.currentValue = 0;
    }
    return candidate;
}

static void OnSameWorldBecameInactive(bool onGameThread);

static uintptr_t WaitForWorldChrMan()
{
    uintptr_t pointerAddress = 0;
    while (!pointerAddress)
    {
        const uintptr_t instruction =
            ScanUniquePattern(WORLD_CHR_MAN_PATTERN_FALLBACK);
        if (instruction)
            pointerAddress = ResolveRipRelative(instruction + 3);
        else
            Sleep(2000);
    }

    for (int attempt = 0; attempt < 600; ++attempt)
    {
        if (*reinterpret_cast<uintptr_t*>(pointerAddress))
            break;
        Sleep(100);
    }
    return pointerAddress;
}

static bool TryReadPointer(uintptr_t address, uintptr_t& value)
{
    value = 0;
    if (address < kMinValidUserPointer)
        return false;

    __try
    {
        value = *reinterpret_cast<uintptr_t*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        value = 0;
        return false;
    }
}

static SharedDamageWorldSnapshot CaptureProductionWorldSnapshot()
{
    SharedDamageWorldSnapshot snapshot{};
    if (!g_worldChrManPtr)
        return snapshot;

    snapshot.worldChrManPointerAddress =
        reinterpret_cast<uintptr_t>(g_worldChrManPtr);

    uintptr_t worldChrMan = 0;
    if (!TryReadPointer(snapshot.worldChrManPointerAddress, worldChrMan) ||
        !worldChrMan)
        return snapshot;

    snapshot.netPlayersSnapshot.worldChrMan = worldChrMan;
    snapshot.worldChrManReadable = true;

    uintptr_t netPlayers = 0;
    if (!TryReadPointer(
            worldChrMan + WORLD_CHR_MAN_NET_PLAYERS_OFFSET, netPlayers) ||
        !netPlayers)
        return snapshot;

    snapshot.netPlayersSnapshot.netPlayers = netPlayers;
    snapshot.netPlayersReadable = true;

    for (int slot = NET_PLAYERS_LOCAL_SLOT;
         slot <= NET_PLAYERS_PRODUCTION_SLOT_LAST;
         ++slot)
    {
        uintptr_t chrIns = 0;
        if (!TryReadPointer(
                netPlayers + NET_PLAYERS_SLOT_STRIDE * slot, chrIns))
            return snapshot;

        snapshot.netPlayersSnapshot.slots[slot] = chrIns;
        if (!chrIns)
            continue;

        uintptr_t vtable = 0;
        if (!TryReadPointer(chrIns, vtable) || !vtable)
            return snapshot;

        snapshot.netPlayersSnapshot.vtables[slot] = vtable;
    }
    snapshot.productionSlotsReadComplete = true;

    snapshot.localChrIns =
        snapshot.netPlayersSnapshot.slots[NET_PLAYERS_LOCAL_SLOT];
    if (!snapshot.localChrIns ||
        !snapshot.netPlayersSnapshot.vtables[NET_PLAYERS_LOCAL_SLOT])
        return snapshot;

    uintptr_t moduleBag = 0;
    if (!TryReadPointer(snapshot.localChrIns + 0x190, moduleBag) ||
        !moduleBag)
        return snapshot;
    snapshot.localModuleBag = moduleBag;

    uintptr_t statModule = 0;
    if (!TryReadPointer(moduleBag, statModule) || !statModule)
        return snapshot;
    snapshot.localStatModule = statModule;
    snapshot.localPlayerResolved = true;

    bool remotePresent = false;
    for (int slot = NET_PLAYERS_REMOTE_SLOT_FIRST;
         slot <= NET_PLAYERS_REMOTE_SLOT_LAST;
         ++slot)
    {
        if (snapshot.netPlayersSnapshot.slots[slot] != 0 &&
            snapshot.netPlayersSnapshot.vtables[slot] != 0)
        {
            remotePresent = true;
            break;
        }
    }

    snapshot.presence = remotePresent
        ? SharedWorldPresence::RemotePlayersPresent
        : SharedWorldPresence::NoRemotePlayers;

    // Diagnostic-only: slots 6–7 never affect production presence/cache.
    for (int slot = NET_PLAYERS_PRODUCTION_SLOT_LAST + 1;
         slot <= NET_PLAYERS_DIAGNOSTIC_SLOT_LAST;
         ++slot)
    {
        uintptr_t chrIns = 0;
        if (!TryReadPointer(
                netPlayers + NET_PLAYERS_SLOT_STRIDE * slot, chrIns))
            continue;

        snapshot.netPlayersSnapshot.slots[slot] = chrIns;
        if (!chrIns)
            continue;

        uintptr_t vtable = 0;
        if (TryReadPointer(chrIns, vtable) && vtable)
            snapshot.netPlayersSnapshot.vtables[slot] = vtable;
    }

    return snapshot;
}

static void UpdateProductionFromSnapshot(
    const SharedDamageWorldSnapshot& snapshot,
    SharedDamageLobbyPresence lobbyPresence,
    bool onGameThread,
    bool& queuesCleared,
    const char*& transitionReason)
{
    queuesCleared = false;
    transitionReason = "none";

    switch (snapshot.presence)
    {
    case SharedWorldPresence::RemotePlayersPresent:
        if (snapshot.localPlayerResolved)
        {
            g_cachedLocalStatModule.store(
                snapshot.localStatModule, memory_order_release);
        }
        if (!g_sameWorldActive.load(memory_order_acquire))
            transitionReason = "remote-present";
        g_sameWorldActive.store(true, memory_order_release);
        break;

    case SharedWorldPresence::NoRemotePlayers:
        if (snapshot.localPlayerResolved)
        {
            g_cachedLocalStatModule.store(
                snapshot.localStatModule, memory_order_release);
        }
        if (g_sameWorldActive.load(memory_order_acquire))
        {
            transitionReason = "no-remote-players";
            g_sameWorldActive.store(false, memory_order_release);
            OnSameWorldBecameInactive(onGameThread);
            g_cachedLocalStatModule.store(0, memory_order_release);
            queuesCleared = true;
        }
        break;

    case SharedWorldPresence::Unavailable:
    default:
        transitionReason = "unavailable";
        break;
    }

    if (lobbyPresence == SharedDamageLobbyPresence::NoRemoteMembers &&
        g_sameWorldActive.load(memory_order_acquire))
    {
        transitionReason = "lobby-below-two";
        g_sameWorldActive.store(false, memory_order_release);
        OnSameWorldBecameInactive(onGameThread);
        g_cachedLocalStatModule.store(0, memory_order_release);
        queuesCleared = true;
    }
}

static void InitializeProductionFromSnapshot(
    const SharedDamageWorldSnapshot& snapshot,
    SharedDamageLobbyPresence lobbyPresence)
{
    if (snapshot.localPlayerResolved)
    {
        g_cachedLocalStatModule.store(
            snapshot.localStatModule, memory_order_release);
    }

    bool queuesCleared = false;
    const char* transitionReason = "none";
    UpdateProductionFromSnapshot(
        snapshot, lobbyPresence, false, queuesCleared, transitionReason);

    if (snapshot.presence == SharedWorldPresence::Unavailable)
        g_sameWorldActive.store(false, memory_order_release);
}

static void ResolveSlotDiagnosticFields(
    SharedDamageBossNetPlayersSnapshot& snapshot, int slot)
{
    __try
    {
        const uintptr_t chrIns = snapshot.slots[slot];
        if (!chrIns)
            return;
        snapshot.moduleBags[slot] =
            *reinterpret_cast<uintptr_t*>(chrIns + 0x190);
        if (!snapshot.moduleBags[slot])
            return;
        snapshot.statModules[slot] =
            *reinterpret_cast<uintptr_t*>(snapshot.moduleBags[slot]);
        if (!snapshot.statModules[slot])
            return;
        snapshot.currentHps[slot] = *reinterpret_cast<int32_t*>(
            snapshot.statModules[slot] + 0x138);
        snapshot.currentHpReadable[slot] = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        snapshot.currentHpReadable[slot] = false;
    }
}

static void PopulateSlotDiagnosticFields(
    SharedDamageSameWorldProbeResult& probe)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return;
    for (int slot = 0; slot < 8; ++slot)
        ResolveSlotDiagnosticFields(probe.snapshot, slot);
}

static int FindMatchingStatModuleSlot(
    const SharedDamageBossNetPlayersSnapshot& snapshot,
    uintptr_t statModule)
{
    if (!statModule)
        return -1;
    for (int slot = 0; slot < 8; ++slot)
    {
        if (snapshot.statModules[slot] == statModule)
            return slot;
    }
    return -1;
}

static bool WorldProbeLayoutChanged(
    const SharedDamageSameWorldProbeResult& previous,
    const SharedDamageSameWorldProbeResult& current)
{
    if (previous.active != current.active ||
        previous.snapshot.worldChrMan != current.snapshot.worldChrMan ||
        previous.snapshot.netPlayers != current.snapshot.netPlayers)
        return true;
    for (int slot = 0; slot < 8; ++slot)
    {
        if (previous.snapshot.slots[slot] != current.snapshot.slots[slot] ||
            previous.snapshot.vtables[slot] != current.snapshot.vtables[slot])
            return true;
    }
    return false;
}

static SharedDamageSameWorldProbeResult ProbeWorldChrManCandidate(
    uintptr_t pointerAddress)
{
    SharedDamageSameWorldProbeResult result{};
    if (!pointerAddress)
        return result;

    uintptr_t worldChrMan = 0;
    if (!TryReadPointer(pointerAddress, worldChrMan) || !worldChrMan)
        return result;
    result.snapshot.worldChrMan = worldChrMan;

    uintptr_t netPlayers = 0;
    if (!TryReadPointer(
            worldChrMan + WORLD_CHR_MAN_NET_PLAYERS_OFFSET, netPlayers) ||
        !netPlayers)
        return result;
    result.snapshot.netPlayers = netPlayers;

    for (int slot = NET_PLAYERS_LOCAL_SLOT;
         slot <= NET_PLAYERS_PRODUCTION_SLOT_LAST;
         ++slot)
    {
        uintptr_t chrIns = 0;
        if (!TryReadPointer(
                netPlayers + NET_PLAYERS_SLOT_STRIDE * slot, chrIns))
            return result;

        result.snapshot.slots[slot] = chrIns;
        if (!chrIns)
            continue;

        uintptr_t vtable = 0;
        if (!TryReadPointer(chrIns, vtable) || !vtable)
            return result;
        result.snapshot.vtables[slot] = vtable;
    }

    for (int slot = NET_PLAYERS_REMOTE_SLOT_FIRST;
         slot <= NET_PLAYERS_REMOTE_SLOT_LAST;
         ++slot)
    {
        if (result.snapshot.slots[slot] != 0 &&
            result.snapshot.vtables[slot] != 0)
        {
            result.active = true;
            break;
        }
    }

    for (int slot = NET_PLAYERS_PRODUCTION_SLOT_LAST + 1;
         slot <= NET_PLAYERS_DIAGNOSTIC_SLOT_LAST;
         ++slot)
    {
        uintptr_t chrIns = 0;
        if (!TryReadPointer(
                netPlayers + NET_PLAYERS_SLOT_STRIDE * slot, chrIns))
            continue;

        result.snapshot.slots[slot] = chrIns;
        if (!chrIns)
            continue;

        uintptr_t vtable = 0;
        if (TryReadPointer(chrIns, vtable) && vtable)
            result.snapshot.vtables[slot] = vtable;
    }

    return result;
}

static void LogBossDiagStartup(
    bool hpWriteHookEnabled,
    bool hpDelta7HookEnabled,
    bool hpDelta8HookEnabled,
    bool callbacksHookEnabled,
    bool sharingReady,
    const SharedDamageHookInstallDiag& installDiag,
    const SharedDamageWorldSnapshot& snapshot)
{
    SharedDamageBossDiagLogStartup(
        hpWriteHookEnabled,
        hpDelta7HookEnabled,
        hpDelta8HookEnabled,
        callbacksHookEnabled,
        sharingReady,
        snapshot.netPlayersSnapshot,
        installDiag);
}

static void ClearPendingDamageContext()
{
    g_pendingDamage = {};
}

static void OnSameWorldBecameInactive(bool onGameThread)
{
    g_damagePendingTotal.store(0, memory_order_release);
    DiscardPendingBroadcastDamage();
    if (onGameThread)
        ClearPendingDamageContext();
}

static const char* PendingSourceToString(PendingDamageSource source)
{
    switch (source)
    {
    case PendingDamageSource::HpDelta7:
        return "hp-delta-7";
    case PendingDamageSource::HpDelta8:
        return "hp-delta-8";
    default:
        return "none";
    }
}

static uint32_t TryCapturePendingRawDamage(
    uintptr_t statModule,
    int32_t deltaHp,
    PendingDamageSource sourceWrapper)
{
    if (deltaHp >= 0)
        return 0;

    const uintptr_t local =
        g_cachedLocalStatModule.load(memory_order_acquire);
    if (local == 0 || statModule != local)
        return 0;

    const int64_t rawDamage64 = -static_cast<int64_t>(deltaHp);
    if (rawDamage64 > numeric_limits<int32_t>::max())
        return 0;

    const uint32_t captureSeq =
        g_nextCaptureSeq.fetch_add(1, memory_order_relaxed);
    g_pendingDamage = {
        statModule,
        static_cast<int32_t>(rawDamage64),
        GetTickCount64(),
        true,
        captureSeq,
        sourceWrapper};
    return captureSeq;
}

static bool TryConsumePendingRawDamage(
    uintptr_t statModule,
    int32_t& damage,
    BossPendingConsumeDiag* diag)
{
    if (diag)
    {
        diag->pendingSeq = 0;
        diag->pendingAgeMs = 0;
        diag->result = "no-pending";
        diag->pendingSource = PendingDamageSource::None;
    }

    if (!g_pendingDamage.active)
        return false;

    if (diag)
    {
        diag->pendingSeq = g_pendingDamage.captureSeq;
        diag->pendingSource = g_pendingDamage.sourceWrapper;
    }

    if (diag)
        diag->pendingAgeMs = GetTickCount64() - g_pendingDamage.tickMs;

    if (g_pendingDamage.statModule != statModule)
    {
        if (diag)
            diag->result = "stat-mismatch";
        g_pendingDamage = {};
        return false;
    }

    if (g_pendingDamage.rawDamage <= 0)
    {
        if (diag)
            diag->result = "invalid-damage";
        g_pendingDamage = {};
        return false;
    }

    const ULONGLONG age = GetTickCount64() - g_pendingDamage.tickMs;
    if (age > PENDING_DAMAGE_TTL_MS)
    {
        if (diag)
            diag->result = "expired";
        g_pendingDamage = {};
        return false;
    }

    damage = g_pendingDamage.rawDamage;
    if (diag)
        diag->result = "matched";
    g_pendingDamage = {};
    return true;
}

struct ProductionSnapshotUpdateResult
{
    bool latchedBefore = false;
    bool latchedAfter = false;
    bool queuesCleared = false;
    const char* transitionReason = "none";
    SharedDamageLobbyPresence lobbyPresence =
        SharedDamageLobbyPresence::Unknown;
};

static ProductionSnapshotUpdateResult PublishProductionSnapshot(
    const SharedDamageWorldSnapshot& snapshot,
    bool onGameThread)
{
    g_lastProductionSnapshot = snapshot;

    ProductionSnapshotUpdateResult result{};
    result.latchedBefore =
        g_sameWorldActive.load(memory_order_acquire);
    result.lobbyPresence = GetSharedDamageLobbyPresence();

    UpdateProductionFromSnapshot(
        snapshot,
        result.lobbyPresence,
        onGameThread,
        result.queuesCleared,
        result.transitionReason);

    result.latchedAfter =
        g_sameWorldActive.load(memory_order_acquire);

    if (result.latchedBefore != result.latchedAfter)
    {
        SharedDamageBossDiagLogSameWorldTransition(
            result.latchedBefore,
            result.latchedAfter,
            snapshot.netPlayersSnapshot);
    }

    return result;
}

static void TryLogUnifiedProductionSnapshot(
    const SharedDamageWorldSnapshot& snapshot,
    const ProductionSnapshotUpdateResult& update,
    uint64_t callbackInvocationCount,
    const char* snapshotSource)
{
    const uint32_t snapshotSeq =
        g_nextSnapshotSeq.fetch_add(1, memory_order_relaxed) + 1;
    SharedDamageBossDiagTryLogUnifiedWorldSnapshot(
        snapshotSeq,
        callbackInvocationCount,
        snapshot,
        update.latchedBefore,
        update.latchedAfter,
        update.lobbyPresence,
        update.transitionReason,
        update.queuesCleared,
        snapshotSource);
}

static void DrainRemoteDamageFromSnapshot(
    uintptr_t localStatModule,
    bool localPlayerResolved,
    SharedWorldPresence presence)
{
    const int64_t pending =
        g_damagePendingTotal.exchange(0, memory_order_acq_rel);
    if (pending <= 0)
        return;

    const int32_t damage = static_cast<int32_t>(
        min<int64_t>(pending, numeric_limits<int32_t>::max()));

    if (!IsSameWorldActive())
    {
        SharedDamageBossDiagTryLogDrainApply(
            pending,
            false,
            "same-world-inactive",
            damage,
            -1,
            -1);
        return;
    }

    if (presence == SharedWorldPresence::Unavailable)
    {
        SharedDamageBossDiagTryLogDrainApply(
            pending,
            false,
            "current-snapshot-unavailable",
            damage,
            -1,
            -1);
        return;
    }

    if (!localPlayerResolved || !localStatModule)
    {
        SharedDamageBossDiagTryLogDrainApply(
            pending,
            false,
            "local-player-unresolved",
            damage,
            -1,
            -1);
        return;
    }

    ApplyDamageToLocalPlayer(localStatModule, damage, pending);
}

static void __fastcall hkHpDelta7(
    uintptr_t statModule, int32_t deltaHp, uint8_t flagA, uint8_t flagB,
    float arg5, float arg6, uint8_t flagC)
{
    const uintptr_t local =
        g_cachedLocalStatModule.load(memory_order_acquire);
    const bool modulesMatch = local != 0 && statModule == local;
    const uintptr_t callerAddress =
        reinterpret_cast<uintptr_t>(_ReturnAddress());
    const uintptr_t moduleBase = GetGameModuleBase();
    const uintptr_t callerRva =
        moduleBase && callerAddress >= moduleBase
            ? callerAddress - moduleBase
            : 0;

    uint32_t captureSeq = 0;
    bool captureRan = false;
    if (deltaHp < 0)
    {
        captureSeq = TryCapturePendingRawDamage(
            statModule, deltaHp, PendingDamageSource::HpDelta7);
        captureRan = captureSeq != 0;
    }

    SharedDamageBossDiagTryLogDelta7Entry(
        statModule,
        local,
        deltaHp,
        modulesMatch,
        callerRva,
        captureRan,
        captureSeq);

    if (deltaHp < 0)
    {
        if (modulesMatch)
        {
            SharedDamageBossDiagTryLogDeltaLocal(
                captureSeq,
                statModule,
                local,
                deltaHp,
                callerRva,
                "hp-delta-7",
                captureRan);
        }
        else
        {
            SharedDamageBossDiagTryLogDeltaNonLocal(
                statModule, local, deltaHp, callerRva);
        }
    }

    fpHpDelta7(statModule, deltaHp, flagA, flagB, arg5, arg6, flagC);
}

static void __fastcall hkHpDelta8(
    uintptr_t statModule, int32_t deltaHp, uint8_t flagA, uint8_t flagB,
    uint8_t flagC, float arg6, float arg7, uint8_t flagD)
{
    const uintptr_t local =
        g_cachedLocalStatModule.load(memory_order_acquire);
    const bool modulesMatch = local != 0 && statModule == local;
    const uintptr_t callerAddress =
        reinterpret_cast<uintptr_t>(_ReturnAddress());
    const uintptr_t moduleBase = GetGameModuleBase();
    const uintptr_t callerRva =
        moduleBase && callerAddress >= moduleBase
            ? callerAddress - moduleBase
            : 0;

    uint32_t captureSeq = 0;
    bool captureRan = false;
    if (deltaHp < 0)
    {
        captureSeq = TryCapturePendingRawDamage(
            statModule, deltaHp, PendingDamageSource::HpDelta8);
        captureRan = captureSeq != 0;
    }

    SharedDamageBossDiagTryLogDelta8Entry(
        statModule,
        local,
        deltaHp,
        modulesMatch,
        callerRva,
        captureRan,
        captureSeq);

    if (deltaHp < 0)
    {
        if (modulesMatch)
        {
            SharedDamageBossDiagTryLogDeltaLocal(
                captureSeq,
                statModule,
                local,
                deltaHp,
                callerRva,
                "hp-delta-8",
                captureRan);
        }
        else
        {
            SharedDamageBossDiagTryLogDeltaNonLocal(
                statModule, local, deltaHp, callerRva);
        }
    }

    fpHpDelta8(
        statModule, deltaHp, flagA, flagB, flagC, arg6, arg7, flagD);
}

static void __fastcall hkDamageFunc(uintptr_t statModule, int32_t newHp)
{
    const uintptr_t callerAddress =
        reinterpret_cast<uintptr_t>(_ReturnAddress());
    if (!g_runCallbacksHookInstalled.load(memory_order_acquire))
    {
        const SharedDamageWorldSnapshot snapshot =
            CaptureProductionWorldSnapshot();
        const ProductionSnapshotUpdateResult update =
            PublishProductionSnapshot(snapshot, true);
        TryLogUnifiedProductionSnapshot(
            snapshot,
            update,
            0,
            "hp-write-fallback");
        DrainRemoteDamageFromSnapshot(
            snapshot.localStatModule,
            snapshot.localPlayerResolved,
            snapshot.presence);
    }

    const uintptr_t local =
        g_cachedLocalStatModule.load(memory_order_acquire);
    if (!local || statModule != local)
    {
        fpDamageFunc(statModule, newHp);
        return;
    }

    const int32_t currentHp =
        *reinterpret_cast<int32_t*>(local + 0x138);
    int32_t rawDamage = 0;
    BossPendingConsumeDiag consumeDiag{};
    const bool hasRawDamage =
        TryConsumePendingRawDamage(local, rawDamage, &consumeDiag);

    fpDamageFunc(statModule, newHp);

    const bool finalDecrease = currentHp > 0 && newHp < currentHp;
    const bool sameWorldActive = IsSameWorldActive();

    if (finalDecrease)
    {
        const char* decision = "no-provenance";
        if (hasRawDamage && rawDamage > 0 && sameWorldActive)
            decision = "broadcast";
        else if (hasRawDamage && rawDamage > 0)
            decision = "same-world-inactive";

        int matchingNetPlayerSlot = -1;
        uintptr_t callerRva = 0;
        if (SharedDamageBossDiagCanLogHpDecrease())
        {
            SharedDamageBossNetPlayersSnapshot diagSnapshot =
                g_lastProductionSnapshot.netPlayersSnapshot;
            SharedDamageSameWorldProbeResult diagProbe{};
            diagProbe.snapshot = diagSnapshot;
            PopulateSlotDiagnosticFields(diagProbe);
            matchingNetPlayerSlot =
                FindMatchingStatModuleSlot(diagProbe.snapshot, statModule);
            const uintptr_t moduleBase = GetGameModuleBase();
            callerRva = moduleBase && callerAddress >= moduleBase
                ? callerAddress - moduleBase
                : 0;
        }

        SharedDamageBossDiagTryLogHpDecrease(
            statModule,
            local,
            local,
            matchingNetPlayerSlot,
            callerRva,
            currentHp,
            newHp,
            hasRawDamage,
            rawDamage,
            consumeDiag.pendingSeq,
            consumeDiag.pendingAgeMs,
            consumeDiag.result,
            PendingSourceToString(consumeDiag.pendingSource),
            decision);
    }

    if (hasRawDamage && rawDamage > 0 && finalDecrease && sameWorldActive)
    {
        BroadcastDamage(rawDamage);
        if (!g_runCallbacksHookInstalled.load(memory_order_acquire))
            FlushBroadcastDamage();
    }
}

static void hkRunCallbacks()
{
    const uint64_t callbackInvocationCount =
        SharedDamageBossDiagNotifyCallbackInvocation();
    fpRunCallbacks();

    const SharedDamageWorldSnapshot snapshot =
        CaptureProductionWorldSnapshot();
    const ProductionSnapshotUpdateResult update =
        PublishProductionSnapshot(snapshot, true);
    TryLogUnifiedProductionSnapshot(
        snapshot,
        update,
        callbackInvocationCount,
        "steam-callback");

    const ULONGLONG now = GetTickCount64();
    ULONGLONG nextProbe =
        g_nextWorldProbeTickMs.load(memory_order_relaxed);
    if (now >= nextProbe &&
        g_nextWorldProbeTickMs.compare_exchange_strong(
            nextProbe, now + 1000, memory_order_relaxed, memory_order_relaxed))
    {
        SharedDamageSameWorldProbeResult productionProbe{};
        productionProbe.snapshot = snapshot.netPlayersSnapshot;
        productionProbe.active =
            snapshot.presence == SharedWorldPresence::RemotePlayersPresent;
        PopulateSlotDiagnosticFields(productionProbe);

        SharedDamageWorldChrManCandidateProbe primaryProbe{};
        primaryProbe.pointerAddress = g_diagPrimaryWorldChrManPtrAddr;
        primaryProbe.probe = ProbeWorldChrManCandidate(primaryProbe.pointerAddress);
        PopulateSlotDiagnosticFields(primaryProbe.probe);

        SharedDamageWorldChrManCandidateProbe fallbackProbe{};
        fallbackProbe.pointerAddress = g_diagFallbackWorldChrManPtrAddr;
        fallbackProbe.probe =
            ProbeWorldChrManCandidate(fallbackProbe.pointerAddress);
        PopulateSlotDiagnosticFields(fallbackProbe.probe);

        const int matchingSlot = FindMatchingStatModuleSlot(
            productionProbe.snapshot, snapshot.localStatModule);
        ++g_worldProbeSampleCount;
        const bool layoutChanged =
            !g_havePreviousWorldProbe ||
            WorldProbeLayoutChanged(g_previousWorldProbe, productionProbe);
        const bool periodicSample =
            g_worldProbeSampleCount <= 2 ||
            (g_worldProbeSampleCount % 10) == 0;
        if (layoutChanged || periodicSample)
        {
            const bool candidatesAlias =
                g_diagPrimaryWorldChrManPtrAddr != 0 &&
                g_diagPrimaryWorldChrManPtrAddr ==
                    g_diagFallbackWorldChrManPtrAddr;
            SharedDamageBossDiagTryLogWorldProbe(
                snapshot.worldChrManPointerAddress,
                productionProbe,
                primaryProbe,
                fallbackProbe,
                candidatesAlias,
                snapshot.localStatModule,
                matchingSlot,
                callbackInvocationCount);
        }
        g_previousWorldProbe = productionProbe;
        g_havePreviousWorldProbe = true;
        LogSharedDamageSteamStateIfChanged(callbackInvocationCount);
    }

    FlushBroadcastDamage();
    DrainRemoteDamageFromSnapshot(
        snapshot.localStatModule,
        snapshot.localPlayerResolved,
        snapshot.presence);
}
}

uintptr_t* g_worldChrManPtr = nullptr;
DamageFunc_t fpDamageFunc = nullptr;

bool IsSameWorldActive()
{
    return g_sameWorldActive.load(memory_order_acquire);
}

void DrainRemoteDamage(
    uintptr_t localStatModule,
    bool localPlayerResolved,
    SharedWorldPresence presence)
{
    DrainRemoteDamageFromSnapshot(
        localStatModule, localPlayerResolved, presence);
}

void EnqueueRemoteDamage(int32_t damage)
{
    if (damage <= 0)
    {
        SharedDamageBossDiagTryLogEnqueue(
            damage, false, "nonpositive-damage", 0);
        return;
    }

    if (!IsSameWorldActive())
    {
        SharedDamageBossDiagTryLogEnqueue(
            damage, false, "same-world-inactive", 0);
        return;
    }

    const int64_t pendingTotal =
        g_damagePendingTotal.fetch_add(damage, memory_order_release) + damage;
    SharedDamageBossDiagTryLogEnqueue(
        damage, true, "accepted", pendingTotal);
}

void ApplyDamageToLocalPlayer(
    uintptr_t statModule, int32_t damage, int64_t pendingAmount)
{
    if (damage <= 0)
    {
        SharedDamageBossDiagTryLogDrainApply(
            pendingAmount,
            false,
            "nonpositive-damage",
            damage,
            -1,
            -1);
        return;
    }

    if (!fpDamageFunc)
    {
        SharedDamageBossDiagTryLogDrainApply(
            pendingAmount,
            false,
            "hp-write-hook-missing",
            damage,
            -1,
            -1);
        return;
    }

    if (!statModule)
    {
        SharedDamageBossDiagTryLogDrainApply(
            pendingAmount,
            false,
            "local-player-unresolved",
            damage,
            -1,
            -1);
        return;
    }

    const int32_t currentHp =
        *reinterpret_cast<int32_t*>(statModule + 0x138);
    const int32_t newHp = max(0, currentHp - damage);
    fpDamageFunc(statModule, newHp);
    SharedDamageBossDiagTryLogDrainApply(
        pendingAmount,
        true,
        "applied",
        damage,
        currentHp,
        newHp);
}

void InitHooks()
{
    bool hpWriteHookEnabled = false;
    bool hpDelta7HookEnabled = false;
    bool hpDelta8HookEnabled = false;
    bool callbacksHookEnabled = false;
    bool sharingReady = false;
    SharedDamageHookInstallDiag installDiag{};
    installDiag.moduleBase = GetGameModuleBase();

    installDiag.primaryWorldChrMan =
        ResolveWorldChrManCandidate(WORLD_CHR_MAN_PATTERN);
    installDiag.fallbackWorldChrMan =
        ResolveWorldChrManCandidate(WORLD_CHR_MAN_PATTERN_FALLBACK);
    g_diagPrimaryWorldChrManPtrAddr =
        installDiag.primaryWorldChrMan.pointerAddress;
    g_diagFallbackWorldChrManPtrAddr =
        installDiag.fallbackWorldChrMan.pointerAddress;

    if (installDiag.fallbackWorldChrMan.pointerAddress != 0)
    {
        g_worldChrManPtr = reinterpret_cast<uintptr_t*>(
            installDiag.fallbackWorldChrMan.pointerAddress);
        for (int attempt = 0; attempt < 600; ++attempt)
        {
            if (*g_worldChrManPtr)
                break;
            Sleep(100);
        }
    }
    else
    {
        g_worldChrManPtr =
            reinterpret_cast<uintptr_t*>(WaitForWorldChrMan());
    }
    installDiag.worldChrManPointerAddress =
        reinterpret_cast<uintptr_t>(g_worldChrManPtr);

    const SharedDamageWorldSnapshot initSnapshot =
        CaptureProductionWorldSnapshot();
    g_lastProductionSnapshot = initSnapshot;
    InitializeProductionFromSnapshot(
        initSnapshot, GetSharedDamageLobbyPresence());

    installDiag.damagePatternMatches =
        CountPatternMatches(DAMAGE_FUNC_PROLOGUE);
    const uintptr_t damageEntry = ScanUniquePattern(DAMAGE_FUNC_PROLOGUE);
    installDiag.damagePatternMatch = damageEntry;
    installDiag.damageEntry = damageEntry;
    installDiag.damageEntryRva = ToRva(damageEntry);
    installDiag.damagePrologueValid = ValidateFunctionEntry(
        damageEntry,
        HP_WRITE_EXPECTED_RVA,
        installDiag.damagePdataBeginRva,
        installDiag.damagePdataEndRva);

    installDiag.hpDelta7Matches =
        CountPatternMatches(HP_DELTA7_WRAPPER_PATTERN);
    const uintptr_t hpDelta7Match =
        ScanUniquePattern(HP_DELTA7_WRAPPER_PATTERN);
    installDiag.hpDelta7PatternMatch = hpDelta7Match;
    const uintptr_t hpDelta7Entry =
        (hpDelta7Match >= HP_DELTA7_WRAPPER_BACKTRACK)
            ? hpDelta7Match - HP_DELTA7_WRAPPER_BACKTRACK
            : 0;
    installDiag.hpDelta7Entry = hpDelta7Entry;
    installDiag.hpDelta7EntryRva = ToRva(hpDelta7Entry);
    installDiag.hpDelta7PrologueValid = ValidateFunctionEntry(
        hpDelta7Entry,
        HP_DELTA7_EXPECTED_RVA,
        installDiag.hpDelta7PdataBeginRva,
        installDiag.hpDelta7PdataEndRva);

    installDiag.hpDelta8Matches =
        CountPatternMatches(HP_DELTA8_WRAPPER_PATTERN);
    const uintptr_t hpDelta8Entry =
        ScanUniquePattern(HP_DELTA8_WRAPPER_PATTERN);
    installDiag.hpDelta8Entry = hpDelta8Entry;
    installDiag.hpDelta8EntryRva = ToRva(hpDelta8Entry);
    installDiag.hpDelta8PrologueValid = ValidateFunctionEntry(
        hpDelta8Entry,
        HP_DELTA8_EXPECTED_RVA,
        installDiag.hpDelta8PdataBeginRva,
        installDiag.hpDelta8PdataEndRva);

    if (!damageEntry || installDiag.damagePatternMatches != 1 ||
        !installDiag.damagePrologueValid)
    {
        installDiag.failedStage = "hp-write-scan-or-pdata";
        LogBossDiagStartup(
            hpWriteHookEnabled,
            hpDelta7HookEnabled,
            hpDelta8HookEnabled,
            callbacksHookEnabled,
            sharingReady,
            installDiag,
            initSnapshot);
        return;
    }

    if (!hpDelta7Entry || installDiag.hpDelta7Matches != 1 ||
        !installDiag.hpDelta7PrologueValid)
    {
        installDiag.failedStage = "hp-delta7-scan-or-pdata";
        LogBossDiagStartup(
            hpWriteHookEnabled,
            hpDelta7HookEnabled,
            hpDelta8HookEnabled,
            callbacksHookEnabled,
            sharingReady,
            installDiag,
            initSnapshot);
        return;
    }

    if (!hpDelta8Entry || installDiag.hpDelta8Matches != 1 ||
        !installDiag.hpDelta8PrologueValid)
    {
        installDiag.failedStage = "hp-delta8-scan-or-pdata";
        LogBossDiagStartup(
            hpWriteHookEnabled,
            hpDelta7HookEnabled,
            hpDelta8HookEnabled,
            callbacksHookEnabled,
            sharingReady,
            installDiag,
            initSnapshot);
        return;
    }

    const MH_STATUS initializeStatus = MH_Initialize();
    installDiag.mhInitializeResult = static_cast<int>(initializeStatus);
    if (initializeStatus != MH_OK &&
        initializeStatus != MH_ERROR_ALREADY_INITIALIZED)
    {
        installDiag.failedStage = "mh-initialize";
        LogBossDiagStartup(
            hpWriteHookEnabled,
            hpDelta7HookEnabled,
            hpDelta8HookEnabled,
            callbacksHookEnabled,
            sharingReady,
            installDiag,
            initSnapshot);
        return;
    }

    const MH_STATUS hpWriteCreateStatus = MH_CreateHook(
        reinterpret_cast<void*>(damageEntry),
        reinterpret_cast<void*>(&hkDamageFunc),
        reinterpret_cast<void**>(&fpDamageFunc));
    installDiag.hpWriteCreateResult = static_cast<int>(hpWriteCreateStatus);

    const MH_STATUS hpDelta7CreateStatus = MH_CreateHook(
        reinterpret_cast<void*>(hpDelta7Entry),
        reinterpret_cast<void*>(&hkHpDelta7),
        reinterpret_cast<void**>(&fpHpDelta7));
    installDiag.hpDelta7CreateResult = static_cast<int>(hpDelta7CreateStatus);

    const MH_STATUS hpDelta8CreateStatus = MH_CreateHook(
        reinterpret_cast<void*>(hpDelta8Entry),
        reinterpret_cast<void*>(&hkHpDelta8),
        reinterpret_cast<void**>(&fpHpDelta8));
    installDiag.hpDelta8CreateResult = static_cast<int>(hpDelta8CreateStatus);

    bool callbacksHookCreated = false;
    const MH_STATUS callbacksCreateStatus = MH_CreateHookApi(
        L"steam_api64", "SteamAPI_RunCallbacks",
        reinterpret_cast<void*>(&hkRunCallbacks),
        reinterpret_cast<void**>(&fpRunCallbacks));
    installDiag.callbacksCreateResult = static_cast<int>(callbacksCreateStatus);
    if (callbacksCreateStatus == MH_OK)
    {
        callbacksHookCreated = true;
        g_runCallbacksHookInstalled.store(true, memory_order_release);
    }
    else
    {
        fpRunCallbacks = nullptr;
        g_runCallbacksHookInstalled.store(false, memory_order_release);
    }

    if (hpWriteCreateStatus != MH_OK)
        installDiag.failedStage = "hp-write-create";
    else if (hpDelta7CreateStatus != MH_OK)
        installDiag.failedStage = "hp-delta7-create";
    else if (hpDelta8CreateStatus != MH_OK)
        installDiag.failedStage = "hp-delta8-create";

    if (hpWriteCreateStatus != MH_OK || hpDelta7CreateStatus != MH_OK ||
        hpDelta8CreateStatus != MH_OK)
    {
        LogBossDiagStartup(
            hpWriteHookEnabled,
            hpDelta7HookEnabled,
            hpDelta8HookEnabled,
            callbacksHookEnabled,
            sharingReady,
            installDiag,
            initSnapshot);
        return;
    }

    const MH_STATUS enableStatus = MH_EnableHook(MH_ALL_HOOKS);
    installDiag.enableResult = static_cast<int>(enableStatus);
    if (enableStatus != MH_OK)
    {
        installDiag.failedStage = "mh-enable";
        installDiag.mhDisableResult =
            static_cast<int>(MH_DisableHook(MH_ALL_HOOKS));
        fpDamageFunc = nullptr;
        fpHpDelta7 = nullptr;
        fpHpDelta8 = nullptr;
        fpRunCallbacks = nullptr;
        g_runCallbacksHookInstalled.store(false, memory_order_release);
        callbacksHookEnabled = false;
        LogBossDiagStartup(
            hpWriteHookEnabled,
            hpDelta7HookEnabled,
            hpDelta8HookEnabled,
            callbacksHookEnabled,
            sharingReady,
            installDiag,
            initSnapshot);
        return;
    }

    hpWriteHookEnabled = true;
    hpDelta7HookEnabled = true;
    hpDelta8HookEnabled = true;
    callbacksHookEnabled = callbacksHookCreated;
    sharingReady = true;
    const SharedDamageWorldSnapshot postHookSnapshot =
        CaptureProductionWorldSnapshot();
    g_lastProductionSnapshot = postHookSnapshot;
    LogBossDiagStartup(
        hpWriteHookEnabled,
        hpDelta7HookEnabled,
        hpDelta8HookEnabled,
        callbacksHookEnabled,
        sharingReady,
        installDiag,
        postHookSnapshot);
    InitializeProductionFromSnapshot(
        postHookSnapshot, GetSharedDamageLobbyPresence());
}

void ShutdownHooks()
{
    ShutdownSharedDamageBossDiag();
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_cachedLocalStatModule.store(0, memory_order_release);
    g_damagePendingTotal.store(0, memory_order_release);
    DiscardPendingBroadcastDamage();
    g_sameWorldActive.store(false, memory_order_release);
    g_runCallbacksHookInstalled.store(false, memory_order_release);
    g_nextWorldProbeTickMs.store(0, memory_order_relaxed);
    g_worldProbeSampleCount = 0;
    g_havePreviousWorldProbe = false;
    g_previousWorldProbe = {};
    g_lastProductionSnapshot = {};
    g_nextSnapshotSeq.store(0, memory_order_relaxed);
    g_diagPrimaryWorldChrManPtrAddr = 0;
    g_diagFallbackWorldChrManPtrAddr = 0;
    g_worldChrManPtr = nullptr;
    fpDamageFunc = nullptr;
    fpHpDelta7 = nullptr;
    fpHpDelta8 = nullptr;
    fpRunCallbacks = nullptr;
}
