#define NOMINMAX
#include "hooks.h"
#include "damage.h"

#include <windows.h>
#include <psapi.h>
#include <MinHook.h>
#include <steam/steam_api.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

namespace
{
enum class SharedWorldPresence : uint8_t
{
    Unavailable = 0,
    NoRemotePlayers = 1,
    RemotePlayersPresent = 2,
};

struct SharedDamageWorldSnapshot
{
    SharedWorldPresence presence = SharedWorldPresence::Unavailable;
    uintptr_t localStatModule = 0;
    bool localPlayerResolved = false;
};

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
constexpr uintptr_t kMinValidUserPointer = 0x10000;

using HpDelta7_t = void(__fastcall*)(
    uintptr_t statModule, int32_t deltaHp, uint8_t flagA, uint8_t flagB,
    float arg5, float arg6, uint8_t flagC);
using HpDelta8_t = void(__fastcall*)(
    uintptr_t statModule, int32_t deltaHp, uint8_t flagA, uint8_t flagB,
    uint8_t flagC, float arg6, float arg7, uint8_t flagD);
using RunCallbacks_t = void(*)();
using DamageFunc_t = void(__fastcall*)(uintptr_t statModule, int32_t newHp);

uintptr_t* g_worldChrManPtr = nullptr;
DamageFunc_t fpDamageFunc = nullptr;
HpDelta7_t fpHpDelta7 = nullptr;
HpDelta8_t fpHpDelta8 = nullptr;
RunCallbacks_t fpRunCallbacks = nullptr;
atomic<uintptr_t> g_cachedLocalStatModule{0};
atomic<int64_t> g_damagePendingTotal{0};
atomic<bool> g_runCallbacksHookInstalled{false};
atomic<bool> g_sameWorldActive{false};

struct PendingDamageContext
{
    uintptr_t statModule = 0;
    int32_t rawDamage = 0;
    ULONGLONG tickMs = 0;
    bool active = false;
};

thread_local PendingDamageContext g_pendingDamage;
constexpr ULONGLONG PENDING_DAMAGE_TTL_MS = 250;

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
    uintptr_t expectedEntryRva)
{
    if (!entry)
        return false;

    const uintptr_t moduleBase = GetGameModuleBase();
    if (!moduleBase)
        return false;

    uintptr_t pdataBegin = 0;
    uintptr_t pdataEnd = 0;
    if (!LookupPdataRange(entry, pdataBegin, pdataEnd))
        return false;

    return ToRva(pdataBegin) == expectedEntryRva && pdataEnd > pdataBegin;
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

    uintptr_t worldChrMan = 0;
    if (!TryReadPointer(
            reinterpret_cast<uintptr_t>(g_worldChrManPtr), worldChrMan) ||
        !worldChrMan)
        return snapshot;

    uintptr_t netPlayers = 0;
    if (!TryReadPointer(
            worldChrMan + WORLD_CHR_MAN_NET_PLAYERS_OFFSET, netPlayers) ||
        !netPlayers)
        return snapshot;

    uintptr_t slots[NET_PLAYERS_REMOTE_SLOT_LAST + 1]{};
    for (int slot = NET_PLAYERS_LOCAL_SLOT;
         slot <= NET_PLAYERS_REMOTE_SLOT_LAST;
         ++slot)
    {
        if (!TryReadPointer(
                netPlayers + NET_PLAYERS_SLOT_STRIDE * slot, slots[slot]))
            return snapshot;

        if (!slots[slot])
            continue;

        uintptr_t vtable = 0;
        if (!TryReadPointer(slots[slot], vtable) || !vtable)
            return snapshot;
    }

    const uintptr_t localChrIns = slots[NET_PLAYERS_LOCAL_SLOT];
    if (!localChrIns)
        return snapshot;

    uintptr_t moduleBag = 0;
    if (!TryReadPointer(localChrIns + 0x190, moduleBag) ||
        !moduleBag)
        return snapshot;

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
        if (slots[slot] != 0)
        {
            remotePresent = true;
            break;
        }
    }

    snapshot.presence = remotePresent
        ? SharedWorldPresence::RemotePlayersPresent
        : SharedWorldPresence::NoRemotePlayers;
    return snapshot;
}

static void UpdateProductionFromSnapshot(
    const SharedDamageWorldSnapshot& snapshot,
    SharedDamageLobbyPresence lobbyPresence,
    bool onGameThread)
{
    switch (snapshot.presence)
    {
    case SharedWorldPresence::RemotePlayersPresent:
        if (snapshot.localPlayerResolved)
        {
            g_cachedLocalStatModule.store(
                snapshot.localStatModule, memory_order_release);
        }
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
            g_sameWorldActive.store(false, memory_order_release);
            OnSameWorldBecameInactive(onGameThread);
            g_cachedLocalStatModule.store(0, memory_order_release);
        }
        break;

    case SharedWorldPresence::Unavailable:
    default:
        break;
    }

    if (lobbyPresence == SharedDamageLobbyPresence::NoRemoteMembers &&
        g_sameWorldActive.load(memory_order_acquire))
    {
        g_sameWorldActive.store(false, memory_order_release);
        OnSameWorldBecameInactive(onGameThread);
        g_cachedLocalStatModule.store(0, memory_order_release);
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

    UpdateProductionFromSnapshot(snapshot, lobbyPresence, false);

    if (snapshot.presence == SharedWorldPresence::Unavailable)
        g_sameWorldActive.store(false, memory_order_release);
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

static bool TryCapturePendingRawDamage(
    uintptr_t statModule,
    int32_t deltaHp)
{
    if (deltaHp >= 0)
        return false;

    const uintptr_t local =
        g_cachedLocalStatModule.load(memory_order_acquire);
    if (local == 0 || statModule != local)
        return false;

    const int64_t rawDamage64 = -static_cast<int64_t>(deltaHp);
    if (rawDamage64 > numeric_limits<int32_t>::max())
        return false;

    g_pendingDamage = {
        statModule,
        static_cast<int32_t>(rawDamage64),
        GetTickCount64(),
        true};
    return true;
}

static bool TryConsumePendingRawDamage(
    uintptr_t statModule,
    int32_t& damage)
{
    if (!g_pendingDamage.active)
        return false;

    if (g_pendingDamage.statModule != statModule)
    {
        g_pendingDamage = {};
        return false;
    }

    if (g_pendingDamage.rawDamage <= 0)
    {
        g_pendingDamage = {};
        return false;
    }

    const ULONGLONG age = GetTickCount64() - g_pendingDamage.tickMs;
    if (age > PENDING_DAMAGE_TTL_MS)
    {
        g_pendingDamage = {};
        return false;
    }

    damage = g_pendingDamage.rawDamage;
    g_pendingDamage = {};
    return true;
}

static void PublishProductionSnapshot(
    const SharedDamageWorldSnapshot& snapshot,
    bool onGameThread)
{
    UpdateProductionFromSnapshot(
        snapshot,
        GetSharedDamageLobbyPresence(),
        onGameThread);
}

static void ApplyDamageToLocalPlayer(
    uintptr_t statModule, int32_t damage)
{
    if (damage <= 0 || !fpDamageFunc || !statModule)
        return;

    const int32_t currentHp =
        *reinterpret_cast<int32_t*>(statModule + 0x138);
    const int32_t newHp = max(0, currentHp - damage);
    fpDamageFunc(statModule, newHp);
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
        return;

    if (presence == SharedWorldPresence::Unavailable)
        return;

    if (!localPlayerResolved || !localStatModule)
        return;

    ApplyDamageToLocalPlayer(localStatModule, damage);
}

static void __fastcall hkHpDelta7(
    uintptr_t statModule, int32_t deltaHp, uint8_t flagA, uint8_t flagB,
    float arg5, float arg6, uint8_t flagC)
{
    if (deltaHp < 0)
        TryCapturePendingRawDamage(statModule, deltaHp);

    fpHpDelta7(statModule, deltaHp, flagA, flagB, arg5, arg6, flagC);
}

static void __fastcall hkHpDelta8(
    uintptr_t statModule, int32_t deltaHp, uint8_t flagA, uint8_t flagB,
    uint8_t flagC, float arg6, float arg7, uint8_t flagD)
{
    if (deltaHp < 0)
        TryCapturePendingRawDamage(statModule, deltaHp);

    fpHpDelta8(
        statModule, deltaHp, flagA, flagB, flagC, arg6, arg7, flagD);
}

static void __fastcall hkDamageFunc(uintptr_t statModule, int32_t newHp)
{
    if (!g_runCallbacksHookInstalled.load(memory_order_acquire))
    {
        const SharedDamageWorldSnapshot snapshot =
            CaptureProductionWorldSnapshot();
        PublishProductionSnapshot(snapshot, true);
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
    const bool hasRawDamage =
        TryConsumePendingRawDamage(local, rawDamage);

    fpDamageFunc(statModule, newHp);

    const bool finalDecrease = currentHp > 0 && newHp < currentHp;
    const bool sameWorldActive = IsSameWorldActive();

    if (hasRawDamage && rawDamage > 0 && finalDecrease && sameWorldActive)
    {
        BroadcastDamage(rawDamage);
        if (!g_runCallbacksHookInstalled.load(memory_order_acquire))
            FlushBroadcastDamage();
    }
}

static void hkRunCallbacks()
{
    fpRunCallbacks();

    const SharedDamageWorldSnapshot snapshot =
        CaptureProductionWorldSnapshot();
    PublishProductionSnapshot(snapshot, true);

    FlushBroadcastDamage();
    DrainRemoteDamageFromSnapshot(
        snapshot.localStatModule,
        snapshot.localPlayerResolved,
        snapshot.presence);
}
}

bool IsSameWorldActive()
{
    return g_sameWorldActive.load(memory_order_acquire);
}

void EnqueueRemoteDamage(int32_t damage)
{
    if (damage <= 0)
        return;

    if (!IsSameWorldActive())
        return;

    g_damagePendingTotal.fetch_add(damage, memory_order_release);
}

void InitHooks()
{
    const uintptr_t worldChrManInstruction =
        ScanUniquePattern(WORLD_CHR_MAN_PATTERN_FALLBACK);
    if (worldChrManInstruction)
    {
        g_worldChrManPtr = reinterpret_cast<uintptr_t*>(
            ResolveRipRelative(worldChrManInstruction + 3));
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

    const SharedDamageWorldSnapshot initSnapshot =
        CaptureProductionWorldSnapshot();
    InitializeProductionFromSnapshot(
        initSnapshot, GetSharedDamageLobbyPresence());

    const uintptr_t damageEntry = ScanUniquePattern(DAMAGE_FUNC_PROLOGUE);
    const uintptr_t hpDelta7Match =
        ScanUniquePattern(HP_DELTA7_WRAPPER_PATTERN);
    const uintptr_t hpDelta7Entry =
        (hpDelta7Match >= HP_DELTA7_WRAPPER_BACKTRACK)
            ? hpDelta7Match - HP_DELTA7_WRAPPER_BACKTRACK
            : 0;
    const uintptr_t hpDelta8Entry =
        ScanUniquePattern(HP_DELTA8_WRAPPER_PATTERN);

    if (!ValidateFunctionEntry(damageEntry, HP_WRITE_EXPECTED_RVA) ||
        !ValidateFunctionEntry(hpDelta7Entry, HP_DELTA7_EXPECTED_RVA) ||
        !ValidateFunctionEntry(hpDelta8Entry, HP_DELTA8_EXPECTED_RVA))
        return;

    const MH_STATUS initializeStatus = MH_Initialize();
    if (initializeStatus != MH_OK &&
        initializeStatus != MH_ERROR_ALREADY_INITIALIZED)
        return;

    const MH_STATUS hpWriteCreateStatus = MH_CreateHook(
        reinterpret_cast<void*>(damageEntry),
        reinterpret_cast<void*>(&hkDamageFunc),
        reinterpret_cast<void**>(&fpDamageFunc));
    const MH_STATUS hpDelta7CreateStatus = MH_CreateHook(
        reinterpret_cast<void*>(hpDelta7Entry),
        reinterpret_cast<void*>(&hkHpDelta7),
        reinterpret_cast<void**>(&fpHpDelta7));
    const MH_STATUS hpDelta8CreateStatus = MH_CreateHook(
        reinterpret_cast<void*>(hpDelta8Entry),
        reinterpret_cast<void*>(&hkHpDelta8),
        reinterpret_cast<void**>(&fpHpDelta8));

    const MH_STATUS callbacksCreateStatus = MH_CreateHookApi(
        L"steam_api64", "SteamAPI_RunCallbacks",
        reinterpret_cast<void*>(&hkRunCallbacks),
        reinterpret_cast<void**>(&fpRunCallbacks));
    if (callbacksCreateStatus == MH_OK)
        g_runCallbacksHookInstalled.store(true, memory_order_release);
    else
    {
        fpRunCallbacks = nullptr;
        g_runCallbacksHookInstalled.store(false, memory_order_release);
    }

    if (hpWriteCreateStatus != MH_OK || hpDelta7CreateStatus != MH_OK ||
        hpDelta8CreateStatus != MH_OK)
    {
        MH_Uninitialize();
        fpDamageFunc = nullptr;
        fpHpDelta7 = nullptr;
        fpHpDelta8 = nullptr;
        fpRunCallbacks = nullptr;
        g_runCallbacksHookInstalled.store(false, memory_order_release);
        return;
    }

    const MH_STATUS enableStatus = MH_EnableHook(MH_ALL_HOOKS);
    if (enableStatus != MH_OK)
    {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        fpDamageFunc = nullptr;
        fpHpDelta7 = nullptr;
        fpHpDelta8 = nullptr;
        fpRunCallbacks = nullptr;
        g_runCallbacksHookInstalled.store(false, memory_order_release);
        return;
    }

    const SharedDamageWorldSnapshot postHookSnapshot =
        CaptureProductionWorldSnapshot();
    InitializeProductionFromSnapshot(
        postHookSnapshot, GetSharedDamageLobbyPresence());
}

void ShutdownHooks()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_cachedLocalStatModule.store(0, memory_order_release);
    g_damagePendingTotal.store(0, memory_order_release);
    DiscardPendingBroadcastDamage();
    g_sameWorldActive.store(false, memory_order_release);
    g_runCallbacksHookInstalled.store(false, memory_order_release);
    g_worldChrManPtr = nullptr;
    fpDamageFunc = nullptr;
    fpHpDelta7 = nullptr;
    fpHpDelta8 = nullptr;
    fpRunCallbacks = nullptr;
}
