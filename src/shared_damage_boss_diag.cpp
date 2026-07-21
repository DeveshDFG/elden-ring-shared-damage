#include "shared_damage_boss_diag.h"
#include "hooks.h"

#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <iomanip>
#include <sstream>
#include <string>

using namespace std;

namespace
{
constexpr uint32_t kMaxDiagLines = 256;
constexpr uint32_t kStartupInitLimit = 16;
constexpr uint32_t kSameWorldTransitionLimit = 16;
constexpr uint32_t kWorldProbeLimit = 24;
constexpr uint32_t kDelta7EntryLimit = 8;
constexpr uint32_t kDelta8EntryLimit = 16;
constexpr uint32_t kDeltaLocalLimit = 24;
constexpr uint32_t kDeltaNonLocalLimit = 4;
constexpr uint32_t kHpDecreaseLimit = 24;
constexpr uint32_t kBroadcastLimit = 16;
constexpr uint32_t kFlushSendLimit = 24;
constexpr uint32_t kReceiveLimit = 16;
constexpr uint32_t kEnqueueLimit = 16;
constexpr uint32_t kDrainApplyLimit = 16;
constexpr uint32_t kSteamStateLimit = 12;
constexpr uint32_t kUnifiedSnapshotLimit = 12;
constexpr uint32_t kUnifiedUnavailableWhileActiveLimit = 8;

mutex g_logMutex;
ofstream g_logStream;
wstring g_resolvedLogPath;
atomic<uint32_t> g_lineCount{0};
atomic<uint32_t> g_eventSeq{0};
atomic<bool> g_loggingDisabled{false};
atomic<bool> g_logOpen{false};
atomic<uint32_t> g_startupInitEventsLogged{0};
atomic<uint32_t> g_sameWorldTransitionEventsLogged{0};
atomic<uint32_t> g_worldProbeEventsLogged{0};
atomic<uint32_t> g_delta7EntryEventsLogged{0};
atomic<uint32_t> g_delta8EntryEventsLogged{0};
atomic<uint32_t> g_deltaLocalEventsLogged{0};
atomic<uint32_t> g_deltaNonLocalEventsLogged{0};
atomic<uint32_t> g_hpDecreaseEventsLogged{0};
atomic<uint32_t> g_broadcastEventsLogged{0};
atomic<uint32_t> g_flushSendEventsLogged{0};
atomic<uint32_t> g_receiveEventsLogged{0};
atomic<uint32_t> g_enqueueEventsLogged{0};
atomic<uint32_t> g_drainApplyEventsLogged{0};
atomic<uint32_t> g_steamStateEventsLogged{0};
atomic<uint32_t> g_unifiedSnapshotEventsLogged{0};
atomic<uint32_t> g_unifiedUnavailableWhileActiveLogged{0};
atomic<uint64_t> g_callbackInvocationCount{0};
atomic<bool> g_startupLogged{false};
atomic<bool> g_localSteamIdLogged{false};
SharedWorldPresence g_lastLoggedPresence = SharedWorldPresence::Unavailable;
bool g_lastLoggedLatch = false;

static string WideToUtf8(const wstring& wide)
{
    if (wide.empty())
        return {};

    const int size = WideCharToMultiByte(
        CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0)
        return {};

    string utf8(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
        utf8.data(), size, nullptr, nullptr);
    return utf8;
}

static void EmitDebugLine(const wstring& message)
{
    OutputDebugStringW(message.c_str());
    OutputDebugStringW(L"\n");
}

static wstring GetEldenRingGameDirectory()
{
    HMODULE module = GetModuleHandleW(L"eldenring.exe");
    if (!module)
        module = GetModuleHandleW(nullptr);

    wchar_t path[MAX_PATH]{};
    if (!module || GetModuleFileNameW(module, path, MAX_PATH) == 0)
        return {};

    wstring folder(path);
    const size_t slash = folder.find_last_of(L"\\/");
    if (slash != wstring::npos)
        folder.resize(slash);
    return folder;
}

static wstring BuildLogFileName()
{
    wostringstream name;
    name << L"shared-damage-boss-check-pid-" << GetCurrentProcessId() << L".txt";
    return name.str();
}

static wstring ToAbsolutePath(const wstring& path)
{
    wchar_t fullPath[MAX_PATH]{};
    if (GetFullPathNameW(path.c_str(), MAX_PATH, fullPath, nullptr) == 0)
        return path;
    return fullPath;
}

static bool WriteLineUnlocked(const string& line)
{
    if (!g_logOpen.load(memory_order_acquire))
        return false;

    if (g_lineCount.load(memory_order_relaxed) >= kMaxDiagLines)
    {
        g_loggingDisabled.store(true, memory_order_release);
        return false;
    }

    if (!g_logStream.is_open())
        return false;

    g_logStream << line << '\n';
    g_logStream.flush();
    g_lineCount.fetch_add(1, memory_order_relaxed);
    if (g_lineCount.load(memory_order_relaxed) >= kMaxDiagLines)
        g_loggingDisabled.store(true, memory_order_release);
    return true;
}

static bool TryConsumeBudget(atomic<uint32_t>& counter, uint32_t limit)
{
    uint32_t current = counter.load(memory_order_relaxed);
    while (current < limit)
    {
        if (counter.compare_exchange_weak(
                current, current + 1, memory_order_relaxed, memory_order_relaxed))
            return true;
    }
    return false;
}

static uint32_t NextEventSeq()
{
    return g_eventSeq.fetch_add(1, memory_order_relaxed) + 1;
}

static void AppendRuntimePrefix(ostringstream& stream)
{
    stream << " eventSeq=" << NextEventSeq()
           << " tickMs=" << GetTickCount64()
           << " processId=" << GetCurrentProcessId()
           << " threadId=" << GetCurrentThreadId()
           << " sameWorldActive="
           << (IsSameWorldActive() ? "true" : "false");
}

static bool WriteRuntimeLine(ostringstream& stream)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;

    lock_guard<mutex> lock(g_logMutex);
    return WriteLineUnlocked(stream.str());
}

static bool WriteStartupLine(ostringstream& stream)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_startupInitEventsLogged, kStartupInitLimit))
        return false;

    lock_guard<mutex> lock(g_logMutex);
    return WriteLineUnlocked(stream.str());
}

static string FormatSlotsAndVtables(const SharedDamageBossNetPlayersSnapshot& snapshot)
{
    ostringstream stream;
    for (int i = 0; i < 8; ++i)
    {
        if (i != 0)
            stream << ' ';
        stream << "slot" << i << '=' << snapshot.slots[i]
               << " vtable" << i << '=' << snapshot.vtables[i];
    }
    return stream.str();
}

static string FormatSlots(const uintptr_t slots[8])
{
    ostringstream stream;
    for (int i = 0; i < 8; ++i)
    {
        if (i != 0)
            stream << ' ';
        stream << "slot" << i << '=' << slots[i];
    }
    return stream.str();
}

static string FormatSlotDetails(
    const SharedDamageBossNetPlayersSnapshot& snapshot)
{
    ostringstream stream;
    for (int i = 0; i < 8; ++i)
    {
        if (i != 0)
            stream << ' ';
        stream << "slot" << i << "ChrIns=" << snapshot.slots[i]
               << " slot" << i << "Vtable=" << snapshot.vtables[i]
               << " slot" << i << "ModuleBag=" << snapshot.moduleBags[i]
               << " slot" << i << "StatModule=" << snapshot.statModules[i]
               << " slot" << i << "CurrentHp=";
        if (snapshot.currentHpReadable[i])
            stream << snapshot.currentHps[i];
        else
            stream << "unreadable";
    }
    return stream.str();
}

static string FormatPrefixedSlotDetails(
    const char* prefix,
    const SharedDamageBossNetPlayersSnapshot& snapshot)
{
    ostringstream stream;
    for (int i = 0; i < 8; ++i)
    {
        if (i != 0)
            stream << ' ';
        stream << prefix << "Slot" << i << '=' << snapshot.slots[i]
               << ' ' << prefix << "Vtable" << i << '='
               << snapshot.vtables[i]
               << ' ' << prefix << "ModuleBag" << i << '='
               << snapshot.moduleBags[i]
               << ' ' << prefix << "StatModule" << i << '='
               << snapshot.statModules[i]
               << ' ' << prefix << "CurrentHp" << i << '=';
        if (snapshot.currentHpReadable[i])
            stream << snapshot.currentHps[i];
        else
            stream << "unreadable";
    }
    return stream.str();
}

static void BeginTaggedRuntimeLine(ostringstream& stream, const char* tag)
{
    stream << "SharedDamageBoss: [" << tag << "]";
}

static const char* PresenceToString(SharedWorldPresence presence)
{
    switch (presence)
    {
    case SharedWorldPresence::NoRemotePlayers:
        return "no-remote";
    case SharedWorldPresence::RemotePlayersPresent:
        return "remote-present";
    default:
        return "unavailable";
    }
}

static const char* LobbyPresenceToString(SharedDamageLobbyPresence presence)
{
    switch (presence)
    {
    case SharedDamageLobbyPresence::NoRemoteMembers:
        return "no-remote";
    case SharedDamageLobbyPresence::RemoteMembersPresent:
        return "remote-present";
    default:
        return "unknown";
    }
}

static string FormatEntryBytes(uintptr_t entry, size_t byteCount)
{
    if (!entry)
        return "unavailable";

    ostringstream stream;
    for (size_t i = 0; i < byteCount; ++i)
    {
        if (i != 0)
            stream << ' ';
        stream << std::hex << std::uppercase
               << static_cast<unsigned>(
                      *reinterpret_cast<const uint8_t*>(entry + i));
    }
    return stream.str();
}

static uintptr_t ToRva(uintptr_t address, uintptr_t moduleBase)
{
    return moduleBase && address >= moduleBase ? address - moduleBase : 0;
}
}

void InitSharedDamageBossDiag()
{
    if constexpr (!kBossDiagnosticsEnabled)
        return;

    lock_guard<mutex> lock(g_logMutex);

    g_lineCount.store(0, memory_order_relaxed);
    g_eventSeq.store(0, memory_order_relaxed);
    g_loggingDisabled.store(false, memory_order_release);
    g_logOpen.store(false, memory_order_release);
    g_startupInitEventsLogged.store(0, memory_order_relaxed);
    g_sameWorldTransitionEventsLogged.store(0, memory_order_relaxed);
    g_worldProbeEventsLogged.store(0, memory_order_relaxed);
    g_delta7EntryEventsLogged.store(0, memory_order_relaxed);
    g_delta8EntryEventsLogged.store(0, memory_order_relaxed);
    g_deltaLocalEventsLogged.store(0, memory_order_relaxed);
    g_deltaNonLocalEventsLogged.store(0, memory_order_relaxed);
    g_hpDecreaseEventsLogged.store(0, memory_order_relaxed);
    g_broadcastEventsLogged.store(0, memory_order_relaxed);
    g_flushSendEventsLogged.store(0, memory_order_relaxed);
    g_receiveEventsLogged.store(0, memory_order_relaxed);
    g_enqueueEventsLogged.store(0, memory_order_relaxed);
    g_drainApplyEventsLogged.store(0, memory_order_relaxed);
    g_steamStateEventsLogged.store(0, memory_order_relaxed);
    g_unifiedSnapshotEventsLogged.store(0, memory_order_relaxed);
    g_unifiedUnavailableWhileActiveLogged.store(0, memory_order_relaxed);
    g_callbackInvocationCount.store(0, memory_order_relaxed);
    g_startupLogged.store(false, memory_order_release);
    g_localSteamIdLogged.store(false, memory_order_release);
    g_lastLoggedPresence = SharedWorldPresence::Unavailable;
    g_lastLoggedLatch = false;
    g_resolvedLogPath.clear();

    if (g_logStream.is_open())
        g_logStream.close();

    const wstring gameDirectory = GetEldenRingGameDirectory();
    if (gameDirectory.empty())
    {
        g_loggingDisabled.store(true, memory_order_release);
        EmitDebugLine(
            L"SharedDamageBoss: diagnostics could not resolve eldenring.exe "
            L"game directory");
        return;
    }

    const wstring fullPath = gameDirectory + L"\\" + BuildLogFileName();
    g_logStream.open(filesystem::path(fullPath), ios::out | ios::trunc);
    if (!g_logStream.is_open())
    {
        g_loggingDisabled.store(true, memory_order_release);
        EmitDebugLine(
            L"SharedDamageBoss: diagnostics could not open log file: " + fullPath);
        return;
    }

    g_resolvedLogPath = ToAbsolutePath(fullPath);
    g_logOpen.store(true, memory_order_release);
    EmitDebugLine(
        L"SharedDamageBoss: diagnostic log path: " + g_resolvedLogPath);

    ostringstream initLine;
    initLine << "SharedDamageBoss: [log-init]"
             << " path=" << WideToUtf8(g_resolvedLogPath)
             << " processId=" << GetCurrentProcessId()
             << " transport=steam"
             << " diagnosticsAlwaysEnabled=true";
    WriteLineUnlocked(initLine.str());
}

void ShutdownSharedDamageBossDiag()
{
    if constexpr (!kBossDiagnosticsEnabled)
        return;

    lock_guard<mutex> lock(g_logMutex);
    g_loggingDisabled.store(true, memory_order_release);
    g_logOpen.store(false, memory_order_release);
    if (g_logStream.is_open())
    {
        g_logStream.flush();
        g_logStream.close();
    }
}

uint64_t SharedDamageBossDiagNotifyCallbackInvocation()
{
    if constexpr (!kBossDiagnosticsEnabled)
        return 0;
    return g_callbackInvocationCount.fetch_add(1, memory_order_relaxed) + 1;
}

void SharedDamageBossDiagLogStartup(
    bool hpWriteHookEnabled,
    bool hpDelta7HookEnabled,
    bool hpDelta8HookEnabled,
    bool callbacksHookEnabled,
    bool sharingReady,
    const SharedDamageBossNetPlayersSnapshot& snapshot,
    const SharedDamageHookInstallDiag& installDiag)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return;

    ostringstream hooks;
    hooks << "SharedDamageBoss: [startup]";
    AppendRuntimePrefix(hooks);
    hooks << " transport=steam"
          << " hpWriteHookEnabled=" << (hpWriteHookEnabled ? "true" : "false")
          << " hpDelta7HookEnabled="
          << (hpDelta7HookEnabled ? "true" : "false")
          << " hpDelta8HookEnabled="
          << (hpDelta8HookEnabled ? "true" : "false")
          << " callbacksHookEnabled="
          << (callbacksHookEnabled ? "true" : "false")
          << " sharingReady=" << (sharingReady ? "true" : "false");
    WriteStartupLine(hooks);

    ostringstream worldCandidates;
    worldCandidates << "SharedDamageBoss: [startup]";
    AppendRuntimePrefix(worldCandidates);
    worldCandidates
        << " primaryPatternMatches="
        << installDiag.primaryWorldChrMan.patternMatches
        << " primaryInstructionRva="
        << installDiag.primaryWorldChrMan.instructionRva
        << " primaryPointerAddress="
        << installDiag.primaryWorldChrMan.pointerAddress
        << " primaryCurrentValue="
        << installDiag.primaryWorldChrMan.currentValue
        << " fallbackPatternMatches="
        << installDiag.fallbackWorldChrMan.patternMatches
        << " fallbackInstructionRva="
        << installDiag.fallbackWorldChrMan.instructionRva
        << " fallbackPointerAddress="
        << installDiag.fallbackWorldChrMan.pointerAddress
        << " fallbackCurrentValue="
        << installDiag.fallbackWorldChrMan.currentValue
        << " productionWorldChrManPointerAddress="
        << installDiag.worldChrManPointerAddress
        << " candidatesAlias="
        << ((installDiag.primaryWorldChrMan.pointerAddress &&
             installDiag.primaryWorldChrMan.pointerAddress ==
                 installDiag.fallbackWorldChrMan.pointerAddress)
                ? "true"
                : "false");
    WriteStartupLine(worldCandidates);

    ostringstream net;
    net << "SharedDamageBoss: [startup]";
    AppendRuntimePrefix(net);
    net << " worldChrMan=" << snapshot.worldChrMan
        << " netPlayers=" << snapshot.netPlayers << ' '
        << FormatSlots(snapshot.slots);
    WriteStartupLine(net);

    ostringstream install;
    install << "SharedDamageBoss: [hook-install]";
    AppendRuntimePrefix(install);
    install << " moduleBase=" << installDiag.moduleBase
            << " failedStage="
            << (installDiag.failedStage ? installDiag.failedStage : "none")
            << " damagePatternMatches=" << installDiag.damagePatternMatches
            << " damagePatternMatch=" << installDiag.damagePatternMatch
            << " damageEntryRva=" << installDiag.damageEntryRva
            << " damagePrologueValid="
            << (installDiag.damagePrologueValid ? "true" : "false")
            << " damagePdataBeginRva=" << installDiag.damagePdataBeginRva
            << " damagePdataEndRva=" << installDiag.damagePdataEndRva
            << " hpDelta7Matches=" << installDiag.hpDelta7Matches
            << " hpDelta7PatternMatch=" << installDiag.hpDelta7PatternMatch
            << " hpDelta7EntryRva=" << installDiag.hpDelta7EntryRva
            << " hpDelta7PrologueValid="
            << (installDiag.hpDelta7PrologueValid ? "true" : "false")
            << " hpDelta7PdataBeginRva=" << installDiag.hpDelta7PdataBeginRva
            << " hpDelta7PdataEndRva=" << installDiag.hpDelta7PdataEndRva
            << " hpDelta8Matches=" << installDiag.hpDelta8Matches
            << " hpDelta8Entry=" << installDiag.hpDelta8Entry
            << " hpDelta8EntryRva=" << installDiag.hpDelta8EntryRva
            << " hpDelta8EntryBytes32="
            << FormatEntryBytes(installDiag.hpDelta8Entry, 32)
            << " hpDelta8PrologueValid="
            << (installDiag.hpDelta8PrologueValid ? "true" : "false")
            << " hpDelta8PdataBeginRva=" << installDiag.hpDelta8PdataBeginRva
            << " hpDelta8PdataEndRva=" << installDiag.hpDelta8PdataEndRva
            << " mhInitializeResult=" << installDiag.mhInitializeResult
            << " hpWriteCreateResult=" << installDiag.hpWriteCreateResult
            << " hpDelta7CreateResult=" << installDiag.hpDelta7CreateResult
            << " hpDelta8CreateResult=" << installDiag.hpDelta8CreateResult
            << " callbacksCreateResult=" << installDiag.callbacksCreateResult
            << " enableResult=" << installDiag.enableResult
            << " mhDisableResult=" << installDiag.mhDisableResult;
    WriteStartupLine(install);
    g_startupLogged.store(true, memory_order_release);
}

void SharedDamageBossDiagLogSameWorldTransition(
    bool activeBefore,
    bool activeAfter,
    const SharedDamageBossNetPlayersSnapshot& snapshot)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return;
    if (!g_startupLogged.load(memory_order_acquire))
        return;
    if (g_loggingDisabled.load(memory_order_acquire))
        return;
    if (!TryConsumeBudget(g_sameWorldTransitionEventsLogged, kSameWorldTransitionLimit))
        return;

    ostringstream stream;
    stream << "SharedDamageBoss: [same-world-transition]";
    AppendRuntimePrefix(stream);
    stream << " activeBefore=" << (activeBefore ? "true" : "false")
           << " activeAfter=" << (activeAfter ? "true" : "false")
           << " worldChrMan=" << snapshot.worldChrMan
           << " netPlayers=" << snapshot.netPlayers << ' '
           << FormatSlotsAndVtables(snapshot)
           << " callbackInvocationCount="
           << g_callbackInvocationCount.load(memory_order_relaxed);
    WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogWorldProbe(
    uintptr_t productionPointerAddress,
    const SharedDamageSameWorldProbeResult& productionProbe,
    const SharedDamageWorldChrManCandidateProbe& primary,
    const SharedDamageWorldChrManCandidateProbe& fallback,
    bool candidatesAlias,
    uintptr_t resolvedLocalStatModule,
    int matchingSlot,
    uint64_t callbackInvocationCount)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_worldProbeEventsLogged, kWorldProbeLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [world-probe]";
    AppendRuntimePrefix(stream);
    stream << " callbackInvocationCount=" << callbackInvocationCount
           << " productionPointerAddress=" << productionPointerAddress
           << " productionWorldChrMan=" << productionProbe.snapshot.worldChrMan
           << " productionNetPlayers=" << productionProbe.snapshot.netPlayers
           << " productionActive="
           << (productionProbe.active ? "true" : "false")
           << " primaryPointerAddress=" << primary.pointerAddress
           << " primaryWorldChrMan=" << primary.probe.snapshot.worldChrMan
           << " primaryNetPlayers=" << primary.probe.snapshot.netPlayers
           << " primaryActive=" << (primary.probe.active ? "true" : "false")
           << " fallbackPointerAddress=" << fallback.pointerAddress
           << " fallbackWorldChrMan=" << fallback.probe.snapshot.worldChrMan
           << " fallbackNetPlayers=" << fallback.probe.snapshot.netPlayers
           << " fallbackActive=" << (fallback.probe.active ? "true" : "false")
           << " candidatesAlias=" << (candidatesAlias ? "true" : "false")
           << " resolvedLocalStatModule=" << resolvedLocalStatModule
           << " matchingSlot=" << matchingSlot << ' '
           << FormatSlotDetails(productionProbe.snapshot) << ' '
           << FormatPrefixedSlotDetails("primary", primary.probe.snapshot)
           << ' '
           << FormatPrefixedSlotDetails("fallback", fallback.probe.snapshot);
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogDelta7Entry(
    uintptr_t statModule,
    uintptr_t cachedLocalStatModule,
    int32_t deltaHp,
    bool modulesMatch,
    uintptr_t callerRva,
    bool captureRan,
    uint32_t captureSeq)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_delta7EntryEventsLogged, kDelta7EntryLimit))
        return false;

    ostringstream stream;
    BeginTaggedRuntimeLine(stream, "delta7-entry");
    AppendRuntimePrefix(stream);
    stream << " statModule=" << statModule
           << " cachedLocalStatModule=" << cachedLocalStatModule
           << " deltaHp=" << deltaHp
           << " modulesMatch=" << (modulesMatch ? "true" : "false")
           << " callerRva=" << callerRva
           << " captureRan=" << (captureRan ? "true" : "false")
           << " captureSeq=" << captureSeq;
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogDelta8Entry(
    uintptr_t statModule,
    uintptr_t cachedLocalStatModule,
    int32_t deltaHp,
    bool modulesMatch,
    uintptr_t callerRva,
    bool captureRan,
    uint32_t captureSeq)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_delta8EntryEventsLogged, kDelta8EntryLimit))
        return false;

    ostringstream stream;
    BeginTaggedRuntimeLine(stream, "delta8-entry");
    AppendRuntimePrefix(stream);
    stream << " statModule=" << statModule
           << " cachedLocalStatModule=" << cachedLocalStatModule
           << " deltaHp=" << deltaHp
           << " modulesMatch=" << (modulesMatch ? "true" : "false")
           << " callerRva=" << callerRva
           << " captureRan=" << (captureRan ? "true" : "false")
           << " captureSeq=" << captureSeq;
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogSteamState(
    uint64_t localSteamId,
    uint64_t lobbyId,
    bool lobbyValid,
    int lobbyMemberCount,
    uint64_t callbackInvocationCount)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_steamStateEventsLogged, kSteamStateLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [steam-state]";
    AppendRuntimePrefix(stream);
    stream << " localSteamId=" << localSteamId
           << " lobbyId=" << lobbyId
           << " lobbyValid=" << (lobbyValid ? "true" : "false")
           << " lobbyMemberCount=" << lobbyMemberCount
           << " callbackInvocationCount=" << callbackInvocationCount;
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagCanLogHpDecrease()
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    return !g_loggingDisabled.load(memory_order_acquire) &&
           g_hpDecreaseEventsLogged.load(memory_order_relaxed) < kHpDecreaseLimit;
}

bool SharedDamageBossDiagTryLogDeltaLocal(
    uint32_t captureSeq,
    uintptr_t statModule,
    uintptr_t cachedLocalStatModule,
    int32_t deltaHp,
    uintptr_t callerRva,
    const char* sourceWrapper,
    bool captureRan)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_deltaLocalEventsLogged, kDeltaLocalLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [delta-local]";
    AppendRuntimePrefix(stream);
    stream << " captureSeq=" << captureSeq
           << " statModule=" << statModule
           << " cachedLocalStatModule=" << cachedLocalStatModule
           << " deltaHp=" << deltaHp
           << " callerRva=" << callerRva
           << " sourceWrapper=" << (sourceWrapper ? sourceWrapper : "none")
           << " captureRan=" << (captureRan ? "true" : "false");
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogDeltaNonLocal(
    uintptr_t statModule,
    uintptr_t cachedLocalStatModule,
    int32_t deltaHp,
    uintptr_t callerRva)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_deltaNonLocalEventsLogged, kDeltaNonLocalLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [delta-nonlocal]";
    AppendRuntimePrefix(stream);
    stream << " statModule=" << statModule
           << " cachedLocalStatModule=" << cachedLocalStatModule
           << " deltaHp=" << deltaHp
           << " callerRva=" << callerRva;
    return WriteRuntimeLine(stream);
}

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
    const char* decision)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_hpDecreaseEventsLogged, kHpDecreaseLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [hp-decrease]";
    AppendRuntimePrefix(stream);
    stream << " statModule=" << statModule
           << " cachedLocalStatModule=" << cachedLocalStatModule
           << " resolvedLocalStatModuleAtEvent=" << resolvedLocalStatModule
           << " matchingNetPlayerSlot=" << matchingNetPlayerSlot
           << " callerRva=" << callerRva
           << " currentHp=" << currentHp
           << " newHp=" << newHp
           << " finalHpDelta=" << (currentHp - newHp)
           << " hasRawDamage=" << (hasRawDamage ? "true" : "false")
           << " rawDamage=" << rawDamage
           << " pendingSeq=" << pendingSeq
           << " pendingAgeMs=" << pendingAgeMs
           << " consumeResult=" << (consumeResult ? consumeResult : "unknown")
           << " pendingSource=" << (pendingSource ? pendingSource : "none")
           << " decision=" << (decision ? decision : "unknown");
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogBroadcast(
    int32_t damage,
    bool accepted,
    const char* reason,
    int64_t pendingTotalAfter)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_broadcastEventsLogged, kBroadcastLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [broadcast]";
    AppendRuntimePrefix(stream);
    stream << " damage=" << damage
           << " accepted=" << (accepted ? "true" : "false")
           << " reason=" << (reason ? reason : "none")
           << " pendingTotalAfter=" << pendingTotalAfter;
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogFlush(
    int64_t pendingAmount,
    const char* outcome,
    uint64_t lobbyId,
    int lobbyMemberCount,
    uint64_t localSteamId,
    uint64_t targetSteamId,
    int sendResult,
    int32_t packetDamage)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_flushSendEventsLogged, kFlushSendLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [flush]";
    AppendRuntimePrefix(stream);
    stream << " pendingAmount=" << pendingAmount
           << " outcome=" << (outcome ? outcome : "unknown")
           << " lobbyId=" << lobbyId
           << " lobbyMemberCount=" << lobbyMemberCount
           << " localSteamId=" << localSteamId
           << " targetSteamId=" << targetSteamId
           << " sendResult=" << sendResult
           << " packetDamage=" << packetDamage;
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogLocalSteamId(uint64_t localSteamId)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (!localSteamId)
        return false;

    bool expected = false;
    if (!g_localSteamIdLogged.compare_exchange_strong(
            expected, true, memory_order_relaxed, memory_order_relaxed))
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_flushSendEventsLogged, kFlushSendLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [steam-local-id]";
    AppendRuntimePrefix(stream);
    stream << " localSteamId=" << localSteamId;
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogReceive(
    int messageSize,
    uint64_t senderSteamId,
    bool valid,
    const char* reason,
    int32_t damage)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_receiveEventsLogged, kReceiveLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [receive]";
    AppendRuntimePrefix(stream);
    stream << " messageSize=" << messageSize
           << " senderSteamId=" << senderSteamId
           << " valid=" << (valid ? "true" : "false")
           << " reason=" << (reason ? reason : "none")
           << " damage=" << damage;
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogEnqueue(
    int32_t damage,
    bool accepted,
    const char* reason,
    int64_t pendingRemoteTotal)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_enqueueEventsLogged, kEnqueueLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [enqueue]";
    AppendRuntimePrefix(stream);
    stream << " damage=" << damage
           << " accepted=" << (accepted ? "true" : "false")
           << " reason=" << (reason ? reason : "none")
           << " pendingRemoteTotal=" << pendingRemoteTotal;
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogDrainApply(
    int64_t pendingAmount,
    bool applied,
    const char* reason,
    int32_t requestedDamage,
    int32_t currentHp,
    int32_t newHp)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;
    if (!TryConsumeBudget(g_drainApplyEventsLogged, kDrainApplyLimit))
        return false;

    ostringstream stream;
    stream << "SharedDamageBoss: [drain-apply]";
    AppendRuntimePrefix(stream);
    stream << " pendingAmount=" << pendingAmount
           << " applied=" << (applied ? "true" : "false")
           << " reason=" << (reason ? reason : "none")
           << " requestedDamage=" << requestedDamage
           << " currentHp=" << currentHp
           << " newHp=" << newHp;
    return WriteRuntimeLine(stream);
}

bool SharedDamageBossDiagTryLogUnifiedWorldSnapshot(
    uint32_t snapshotSeq,
    uint64_t callbackInvocationCount,
    const SharedDamageWorldSnapshot& snapshot,
    bool latchedBefore,
    bool latchedAfter,
    SharedDamageLobbyPresence lobbyPresence,
    const char* transitionReason,
    bool queuesCleared,
    const char* snapshotSource)
{
    if constexpr (!kBossDiagnosticsEnabled)
        return false;
    if (g_loggingDisabled.load(memory_order_acquire))
        return false;

    const bool presenceChanged =
        snapshot.presence != g_lastLoggedPresence;
    const bool latchChanged = latchedBefore != latchedAfter;
    const bool unavailableWhileActive =
        snapshot.presence == SharedWorldPresence::Unavailable &&
        latchedAfter;

    bool shouldLog = false;
    bool useOrdinaryBudget = false;
    bool useUnavailableBudget = false;

    if (g_unifiedSnapshotEventsLogged.load(memory_order_relaxed) <
        kUnifiedSnapshotLimit)
    {
        shouldLog = true;
        useOrdinaryBudget = true;
    }
    else if (presenceChanged)
    {
        shouldLog = true;
    }
    else if (latchChanged)
    {
        shouldLog = true;
    }
    else if (unavailableWhileActive &&
             g_unifiedUnavailableWhileActiveLogged.load(
                 memory_order_relaxed) <
                 kUnifiedUnavailableWhileActiveLimit)
    {
        shouldLog = true;
        useUnavailableBudget = true;
    }

    if (!shouldLog)
        return false;

    if (useOrdinaryBudget)
        g_unifiedSnapshotEventsLogged.fetch_add(1, memory_order_relaxed);

    if (useUnavailableBudget)
    {
        g_unifiedUnavailableWhileActiveLogged.fetch_add(
            1, memory_order_relaxed);
    }
    else if (useOrdinaryBudget && unavailableWhileActive &&
             g_unifiedUnavailableWhileActiveLogged.load(
                 memory_order_relaxed) <
                 kUnifiedUnavailableWhileActiveLimit)
    {
        g_unifiedUnavailableWhileActiveLogged.fetch_add(
            1, memory_order_relaxed);
    }

    g_lastLoggedPresence = snapshot.presence;
    g_lastLoggedLatch = latchedAfter;

    ostringstream stream;
    stream << "SharedDamageBoss: [unified-world-snapshot]";
    AppendRuntimePrefix(stream);
    stream << " snapshotSeq=" << snapshotSeq
           << " snapshotSource="
           << (snapshotSource ? snapshotSource : "unknown")
           << " callbackInvocationCount=" << callbackInvocationCount
           << " pointerAddress=" << snapshot.worldChrManPointerAddress
           << " worldChrMan=" << snapshot.netPlayersSnapshot.worldChrMan
           << " netPlayers=" << snapshot.netPlayersSnapshot.netPlayers
           << ' ' << FormatSlots(snapshot.netPlayersSnapshot.slots)
           << ' ' << FormatSlotsAndVtables(snapshot.netPlayersSnapshot)
           << " localChrIns=" << snapshot.localChrIns
           << " localModuleBag=" << snapshot.localModuleBag
           << " localStatModule=" << snapshot.localStatModule
           << " worldChrManReadable="
           << (snapshot.worldChrManReadable ? "true" : "false")
           << " netPlayersReadable="
           << (snapshot.netPlayersReadable ? "true" : "false")
           << " slotsReadComplete="
           << (snapshot.productionSlotsReadComplete ? "true" : "false")
           << " localPlayerResolved="
           << (snapshot.localPlayerResolved ? "true" : "false")
           << " presence=" << PresenceToString(snapshot.presence)
           << " latchedBefore=" << (latchedBefore ? "true" : "false")
           << " latchedAfter=" << (latchedAfter ? "true" : "false")
           << " lobbyPresence=" << LobbyPresenceToString(lobbyPresence)
           << " transitionReason="
           << (transitionReason ? transitionReason : "none")
           << " queuesCleared=" << (queuesCleared ? "true" : "false");
    return WriteRuntimeLine(stream);
}
