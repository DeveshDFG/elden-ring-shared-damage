#define NOMINMAX
#include "destined_death_hooks.h"

#include <windows.h>
#include <psapi.h>
#include <MinHook.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

namespace
{
constexpr int32_t DESTINED_DEATH_SPEFFECT_ID = 90061;
constexpr int32_t PERFECT_DEFLECT_MARKER_ID = 102001;

constexpr uintptr_t CHRINS_SPEFFECT_MANAGER_OFFSET = 0x178;
constexpr uintptr_t SPEFFECT_MANAGER_FIRST_NODE_OFFSET = 0x8;
constexpr uintptr_t SPEFFECT_NODE_ID_OFFSET = 0x8;
constexpr uintptr_t SPEFFECT_NODE_NEXT_OFFSET = 0x30;
constexpr int SPEFFECT_TRAVERSAL_CAP = 512;

constexpr uintptr_t HIGH_LEVEL_SPEFFECT_ENTRY_BACKTRACK = 0x1D;
constexpr uintptr_t HIGH_LEVEL_TO_INNER_CALL_OFFSET = 0x8D;
constexpr const char* HIGH_LEVEL_SPEFFECT_PATTERN =
    "0F 28 0D ? ? ? ? ? 8D ? ? 0F 29 ? ? ? 0F B6 D8";

using ChrInsApplySpEffectInner_t = bool(__fastcall*)(
    uintptr_t targetChrIns,
    int32_t spEffectId,
    uintptr_t sourceChrIns,
    uint32_t flag,
    void* stackArg5,
    void* stackArg6,
    uint8_t stackArg7,
    uint8_t stackArg8,
    uint8_t stackArg9);

ChrInsApplySpEffectInner_t fpChrInsApplySpEffectInner = nullptr;

enum class ActiveSpEffectResult
{
    Present,
    Absent,
    Invalid
};

class ReadableRegionCache
{
public:
    bool Contains(uintptr_t address, size_t size) const
    {
        return address >= begin_ &&
               size <= end_ - begin_ &&
               address - begin_ <= end_ - begin_ - size;
    }

    bool Ensure(uintptr_t address, size_t size)
    {
        if (Contains(address, size))
            return true;

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(
                reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
            return false;
        if (mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
            return false;

        const DWORD protection = mbi.Protect & 0xff;
        const bool readable =
            protection == PAGE_READONLY ||
            protection == PAGE_READWRITE ||
            protection == PAGE_WRITECOPY ||
            protection == PAGE_EXECUTE_READ ||
            protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY;
        if (!readable)
            return false;

        begin_ = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        end_ = begin_ + mbi.RegionSize;
        return Contains(address, size);
    }

private:
    uintptr_t begin_ = 0;
    uintptr_t end_ = 0;
};

static uintptr_t GetGameModuleBase()
{
    HMODULE module = GetModuleHandleA("eldenring.exe");
    if (!module)
        module = GetModuleHandleA(nullptr);
    return reinterpret_cast<uintptr_t>(module);
}

static bool IsExecutableAddress(uintptr_t address)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(
            reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;
    if (mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
        return false;

    const DWORD protection = mbi.Protect & 0xff;
    return protection == PAGE_EXECUTE ||
           protection == PAGE_EXECUTE_READ ||
           protection == PAGE_EXECUTE_READWRITE ||
           protection == PAGE_EXECUTE_WRITECOPY;
}

static bool SameCommittedRegion(uintptr_t first, uintptr_t second)
{
    MEMORY_BASIC_INFORMATION firstInfo{};
    MEMORY_BASIC_INFORMATION secondInfo{};
    if (VirtualQuery(
            reinterpret_cast<void*>(first), &firstInfo, sizeof(firstInfo)) != sizeof(firstInfo) ||
        VirtualQuery(
            reinterpret_cast<void*>(second), &secondInfo, sizeof(secondInfo)) != sizeof(secondInfo))
        return false;
    return firstInfo.State == MEM_COMMIT &&
           secondInfo.State == MEM_COMMIT &&
           firstInfo.BaseAddress == secondInfo.BaseAddress &&
           firstInfo.RegionSize == secondInfo.RegionSize;
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
    uintptr_t regionAddress =
        startFrom > moduleBase ? startFrom : moduleBase;
    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQuery(
               reinterpret_cast<void*>(regionAddress), &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        const uintptr_t regionBase =
            reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        if (regionBase >= scanEnd)
            break;

        const DWORD protection = mbi.Protect & 0xff;
        const bool executable =
            mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
            (protection == PAGE_EXECUTE_READ ||
             protection == PAGE_EXECUTE_READWRITE ||
             protection == PAGE_EXECUTE_WRITECOPY);

        if (executable)
        {
            const uintptr_t regionEnd =
                min(regionBase + mbi.RegionSize, scanEnd);
            const uintptr_t scanStart =
                startFrom > regionBase ? startFrom : regionBase;
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

static uintptr_t ResolveE8CallTarget(uintptr_t instruction)
{
    ReadableRegionCache readable;
    if (!readable.Ensure(instruction, 5) ||
        *reinterpret_cast<const uint8_t*>(instruction) != 0xE8)
        return 0;
    const int32_t relative =
        *reinterpret_cast<const int32_t*>(instruction + 1);
    return instruction + 5 + relative;
}

static bool HasExpectedHighLevelPrologue(uintptr_t address)
{
    static constexpr uint8_t expected[] = {0x48, 0x8B, 0xC4};
    ReadableRegionCache readable;
    return readable.Ensure(address, sizeof(expected)) &&
           memcmp(reinterpret_cast<void*>(address), expected, sizeof(expected)) == 0;
}

static bool HasExpectedInnerPrologue(uintptr_t address)
{
    static constexpr uint8_t expected[] = {
        0x48, 0x8B, 0xC4, 0x57, 0x41, 0x54, 0x41, 0x55,
        0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x50};
    ReadableRegionCache readable;
    return readable.Ensure(address, sizeof(expected)) &&
           memcmp(reinterpret_cast<void*>(address), expected, sizeof(expected)) == 0;
}

static uintptr_t ResolveInnerApplyTarget()
{
    const uintptr_t match =
        ScanUniquePattern(HIGH_LEVEL_SPEFFECT_PATTERN);
    if (match < HIGH_LEVEL_SPEFFECT_ENTRY_BACKTRACK)
        return 0;

    const uintptr_t highLevelEntry =
        match - HIGH_LEVEL_SPEFFECT_ENTRY_BACKTRACK;
    const uintptr_t innerEntry = ResolveE8CallTarget(
        highLevelEntry + HIGH_LEVEL_TO_INNER_CALL_OFFSET);

    if (!innerEntry ||
        !IsExecutableAddress(highLevelEntry) ||
        !IsExecutableAddress(innerEntry) ||
        !SameCommittedRegion(highLevelEntry, match) ||
        !SameCommittedRegion(highLevelEntry, innerEntry) ||
        !HasExpectedHighLevelPrologue(highLevelEntry) ||
        !HasExpectedInnerPrologue(innerEntry))
        return 0;

    return innerEntry;
}

static ActiveSpEffectResult HasActiveSpEffectImpl(
    uintptr_t chrIns, int32_t wantedEffectId)
{
    if (!chrIns)
        return ActiveSpEffectResult::Invalid;

    ReadableRegionCache objectRegion;
    if (!objectRegion.Ensure(
            chrIns + CHRINS_SPEFFECT_MANAGER_OFFSET, sizeof(uintptr_t)))
        return ActiveSpEffectResult::Invalid;

    const uintptr_t manager =
        *reinterpret_cast<const uintptr_t*>(
            chrIns + CHRINS_SPEFFECT_MANAGER_OFFSET);
    if (!manager)
        return ActiveSpEffectResult::Absent;

    ReadableRegionCache listRegion;
    if (!listRegion.Ensure(
            manager + SPEFFECT_MANAGER_FIRST_NODE_OFFSET, sizeof(uintptr_t)))
        return ActiveSpEffectResult::Invalid;

    uintptr_t node =
        *reinterpret_cast<const uintptr_t*>(
            manager + SPEFFECT_MANAGER_FIRST_NODE_OFFSET);

    for (int visits = 0; node; ++visits)
    {
        if (visits >= SPEFFECT_TRAVERSAL_CAP ||
            !listRegion.Ensure(
                node + SPEFFECT_NODE_ID_OFFSET, sizeof(int32_t)) ||
            !listRegion.Ensure(
                node + SPEFFECT_NODE_NEXT_OFFSET, sizeof(uintptr_t)))
            return ActiveSpEffectResult::Invalid;

        if (*reinterpret_cast<const int32_t*>(
                node + SPEFFECT_NODE_ID_OFFSET) == wantedEffectId)
            return ActiveSpEffectResult::Present;

        const uintptr_t next =
            *reinterpret_cast<const uintptr_t*>(
                node + SPEFFECT_NODE_NEXT_OFFSET);
        if (next == node)
            return ActiveSpEffectResult::Invalid;
        node = next;
    }

    return ActiveSpEffectResult::Absent;
}

static ActiveSpEffectResult HasActiveSpEffect(
    uintptr_t chrIns, int32_t wantedEffectId)
{
    __try
    {
        return HasActiveSpEffectImpl(chrIns, wantedEffectId);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return ActiveSpEffectResult::Invalid;
    }
}

static bool __fastcall hkChrInsApplySpEffectInner(
    uintptr_t targetChrIns,
    int32_t spEffectId,
    uintptr_t sourceChrIns,
    uint32_t flag,
    void* stackArg5,
    void* stackArg6,
    uint8_t stackArg7,
    uint8_t stackArg8,
    uint8_t stackArg9)
{
    if (spEffectId == DESTINED_DEATH_SPEFFECT_ID &&
        HasActiveSpEffect(
            targetChrIns, PERFECT_DEFLECT_MARKER_ID) ==
            ActiveSpEffectResult::Present)
        return false;

    return fpChrInsApplySpEffectInner(
        targetChrIns,
        spEffectId,
        sourceChrIns,
        flag,
        stackArg5,
        stackArg6,
        stackArg7,
        stackArg8,
        stackArg9);
}
}

bool InitDestinedDeathHooks()
{
    const uintptr_t innerEntry = ResolveInnerApplyTarget();
    if (!innerEntry)
        return false;

    const MH_STATUS initializeStatus = MH_Initialize();
    if (initializeStatus != MH_OK &&
        initializeStatus != MH_ERROR_ALREADY_INITIALIZED)
        return false;

    if (MH_CreateHook(
            reinterpret_cast<void*>(innerEntry),
            reinterpret_cast<void*>(&hkChrInsApplySpEffectInner),
            reinterpret_cast<void**>(&fpChrInsApplySpEffectInner)) != MH_OK)
        return false;

    const MH_STATUS enableStatus =
        MH_EnableHook(reinterpret_cast<void*>(innerEntry));
    return enableStatus == MH_OK ||
           enableStatus == MH_ERROR_ENABLED;
}
