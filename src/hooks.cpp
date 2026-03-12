#define NOMINMAX
#include "hooks.h"
#include "damage.h"
#include <fstream>
#include "ModUtils.h"
#include <MinHook.h>
#include <cstdint>
#include <psapi.h>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <set>
#include <vector>
#include <steam/steam_api.h>

// WorldChrManImp pointer patterns — RIP-relative MOV, double-dereference.
// Scan returns address of the instruction; the 4-byte RIP offset sits at +3,
// instruction size is 7. RelativeToAbsoluteAddress(scan + 3) yields the address
// of the game's static WorldChrManImp* variable.
//
// Two patterns, mirroring the practice tool's fallback list exactly.
// The primary uses MOV RAX (48 8B 05); the fallback uses MOV RSI (48 8B 35).
// Both point at WorldChrManImp; both use the same offset/instr-size params (3, 7).
// Source: veeenu/eldenring-practice-tool aob_scans.rs, samjviana/souls_vision
static const char* WORLD_CHR_MAN_PATTERN =
    "48 8b 05 ? ? ? ? 48 85 c0 74 0f 48 39 88 ? ? ? ? 75 06 89 b1 5c 03 00 00 0f 28 05 ? ? ? ? 4c 8d 45 e7";
static const char* WORLD_CHR_MAN_PATTERN_FALLBACK =
    "48 8b 35 ? ? ? ? 48 85 f6 ? ? bb 01 00 00 00 89 5c 24 20 48 8b b6";

// These patterns locate an instruction WITHIN the damage function, not its entry
// point. FindFunctionStart() scans backward from the match to find the actual
// function prologue before handing the address to MinHook.
//
// Try the 1.10+ pattern first; fall back to the earlier one.
// If both fail after a game update, open eldenring.exe in IDA/Ghidra, locate the
// function containing these bytes, and derive a new AoB from its first instruction.
// Source: kh0nsu/FromAobScan
static const char* DAMAGE_PATTERN_LATE =
    "29 43 08 83 7b 08 00 89 83 ? ? 00 00 7f ? 80 bb ? ? 00 00 00 75 ?";
static const char* DAMAGE_PATTERN_EARLY =
    "89 4b 08 48 85 f6 74 ? 48 8d 54 24 ? 48 8b ce e8 ? ? ? ? eb ?";
// Direct prologue pattern confirmed via x64dbg on 1.16.1.
// Preferred over mid-function AoB + backward scan — unambiguous, offset = 0.
// Source: x64dbg inspection of the damage function entry point.
// Confirmed via Cheat Engine: HP write at RVA 0x437052 (MOV [RCX+138], EAX)
// is inside sub_7FF7D3CB7000. Prologue bytes verified in x64dbg.
static const char* DAMAGE_FUNC_PROLOGUE =
    "48 89 5c 24 18 48 89 6c 24 20 89 54 24 10 56 57 41 56 48 83 ec 30";

// Generic HP-delta wrapper that computes new HP from a signed delta before
// forwarding into the final HP-write function. The match sits 0x42 bytes into
// the wrapper on 1.16.1; subtract that amount to reach the true function entry.
// Local binary analysis shows this path has multiple callers and is exercised
// before lethal writes are clamped/sentinelized.
static const char* HP_DELTA_WRAPPER_PATTERN =
    "03 9f 38 01 00 00 85 db 7f ? 48 8b cf e8 ? ? ? ? 84 c0 74 ? "
    "bb 01 00 00 00 0f b6 44 24 70 44 0f b6 c6 f3 0f 10 44 24 68 "
    "8b d3 f3 0f 10 5c 24 60 48 8b cf";
static constexpr uintptr_t HP_DELTA_WRAPPER_BACKTRACK = 0x42;

// AddSpEffect mid-function pattern — matches a sequence inside the function body.
// The function entry is exactly 0x1D (29) bytes before the match.
// Source: The Grand Archives Elden Ring CT-TGA, SpEffect_code.cea
// Calling convention (x64 fastcall):
//   rcx = ChrIns*   (local player character instance)
//   rdx = int32_t   (SpEffect ID)
//   r8  = int32_t   (flag; pass 1)
static const char* ADD_SPEFFECT_PATTERN =
    "0f 28 0d ? ? ? ? ? 8d ? ? 0f 29 ? ? ? 0f b6 d8";

// Address of the game's WorldChrManImp* static variable.
// Dereference at hook time to get the live instance pointer.
uintptr_t* g_worldChrManPtr = nullptr;

DamageFunc_t fpDamageFunc = nullptr;

// Pre-clamp HP-delta wrapper: applies a signed delta, clamps, then forwards to
// the final HP-write path. Used to capture raw incoming damage before lethal
// writes collapse to a sentinel or to the victim's remaining HP.
typedef void(__fastcall* DamageDeltaFunc_t)(
    uintptr_t statModule, int32_t deltaHp, uint8_t flagA, uint8_t flagB,
    float arg5, float arg6, uint8_t flagC
);
static DamageDeltaFunc_t fpDamageDeltaFunc = nullptr;

// AddSpEffect: apply a SpEffect to a ChrIns immediately.
// Discovered via The Grand Archives CT-TGA SpEffect_code.cea.
typedef void(__fastcall* AddSpEffect_t)(uintptr_t chrIns, int32_t spEffectId, int32_t flag);
static AddSpEffect_t fpAddSpEffect = nullptr;

// Returns true if the 3 bytes at `addr` look like a common x64 MSVC function prologue.
static bool LooksLikeProlog(uintptr_t addr)
{
    const uint8_t b0 = *reinterpret_cast<uint8_t*>(addr);
    const uint8_t b1 = *reinterpret_cast<uint8_t*>(addr + 1);
    const uint8_t b2 = *reinterpret_cast<uint8_t*>(addr + 2);

    // Reliable x64 MSVC prologue signals only — patterns rare enough in function
    // bodies that a match at a 16-byte-aligned address strongly implies a start:
    //
    //   40/41 + 50-57  — REX.B PUSH r64  (push r8-r15 or REX-prefixed callee-save)
    //   48 83 EC xx    — SUB RSP, imm8   (frame allocation)
    //   48 81 EC xx    — SUB RSP, imm32  (large frame allocation)
    //   48 89 4C/54/5C/74/7C 24  — MOV [RSP+disp8], reg  (incoming arg spill)
    //
    // Excluded deliberately:
    //   53/55/56/57  — bare PUSH RBX/RBP/RSI/RDI: occur constantly mid-function,
    //                  too many false positives in practice.
    //   48 8B ??     — MOV reg, [mem]: a load opcode, never a prologue.
    return ((b0 == 0x40 || b0 == 0x41) && (b1 >= 0x50 && b1 <= 0x57)) ||
           (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC)                    ||
           (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC)                    ||
           (b0 == 0x48 && b1 == 0x89 && (b2 == 0x4C || b2 == 0x54 ||
                                          b2 == 0x5C || b2 == 0x74 ||
                                          b2 == 0x7C));
}

// Scan backward from a mid-function address to find the enclosing function's
// entry point. Three strategies are tried in order:
//
//   1. INT3 (CC) padding — standard MSVC between-function padding.
//   2. NOP  (90) padding — used by some compilers/obfuscators instead of CC.
//   3. 16-byte alignment scan — Elden Ring functions are 16-byte aligned;
//      walk backward in 16-byte steps checking for a valid prologue.
//      Arxan may use no padding at all, making (1) and (2) unreliable.
//
// If all three fail, dumps the 32 bytes before the match to DebugView so the
// actual padding bytes can be inspected and detection improved.
//
// Returns 0 if no suitable start is found within MAX_BACK bytes.
static uintptr_t FindFunctionStart(uintptr_t midAddr)
{
    OutputDebugStringA("[SharedDamage] FindFunctionStart called\n");
    static const uintptr_t MAX_BACK = 0x500; // 1280 bytes — Arxan functions can be large

    // --- Strategy 1: INT3 (CC) padding ---
    // Walk backward byte by byte. Every time we land on a CC, skip the full
    // CC run to find the candidate byte after it. Log the candidate and the
    // LooksLikeProlog result each time so spurious mid-function CCs are visible.
    // After a failed LooksLikeProlog the for-loop's p-- steps back one byte and
    // the scan continues — it does NOT stop at the first CC found.
    for (uintptr_t p = midAddr - 1; p > midAddr - MAX_BACK; p--)
    {
        if (*reinterpret_cast<uint8_t*>(p) != 0xCC)
            continue;

        // Skip the entire contiguous CC run so candidate points to the byte
        // immediately after all the padding (or after this lone CC byte).
        uintptr_t candidate = p + 1;
        while (*reinterpret_cast<uint8_t*>(candidate) == 0xCC)
            candidate++;

        if (candidate >= midAddr)
            break;

        const uint8_t b0 = *reinterpret_cast<const uint8_t*>(candidate);
        const uint8_t b1 = *reinterpret_cast<const uint8_t*>(candidate + 1);
        const uint8_t b2 = *reinterpret_cast<const uint8_t*>(candidate + 2);
        const int     ok = LooksLikeProlog(candidate) ? 1 : 0;

        char dbg[128];
        sprintf_s(dbg,
                  "[SharedDamage] S1 candidate %p: %02x %02x %02x -> LooksLikeProlog=%d\n",
                  reinterpret_cast<void*>(candidate), b0, b1, b2, ok);
        OutputDebugStringA(dbg);

        if (ok)
        {
            OutputDebugStringA("[SharedDamage] FindFunctionStart: found via CC padding\n");
            return candidate;
        }
        // LooksLikeProlog failed — this CC was an operand byte embedded in code,
        // not inter-function padding. The for-loop's p-- continues the backward
        // scan naturally; no explicit action needed here.
    }

    // --- Strategy 2: NOP (90) padding ---
    for (uintptr_t p = midAddr - 1; p > midAddr - MAX_BACK; p--)
    {
        if (*reinterpret_cast<uint8_t*>(p) != 0x90)
            continue;

        uintptr_t candidate = p + 1;
        while (*reinterpret_cast<uint8_t*>(candidate) == 0x90)
            candidate++;

        if (candidate >= midAddr)
            break;

        if (LooksLikeProlog(candidate))
        {
            OutputDebugStringA("[SharedDamage] FindFunctionStart: found via NOP padding\n");
            return candidate;
        }
    }

    // --- Strategy 3: 16-byte alignment scan ---
    // Round down to nearest 16-byte boundary, then step backward by 16 at a time.
    // Log every candidate so we can see exactly which addresses are tested and
    // why a particular one is accepted or rejected.
    {
        uintptr_t candidate = midAddr & ~static_cast<uintptr_t>(0xF);
        const uintptr_t limit = midAddr - MAX_BACK;
        while (candidate > limit)
        {
            const uint8_t b0 = *reinterpret_cast<const uint8_t*>(candidate);
            const uint8_t b1 = *reinterpret_cast<const uint8_t*>(candidate + 1);
            const uint8_t b2 = *reinterpret_cast<const uint8_t*>(candidate + 2);
            const bool    ok = LooksLikeProlog(candidate);

            char dbg[128];
            sprintf_s(dbg,
                      "[SharedDamage] S3 check %p (-%zu): %02x %02x %02x -> %s\n",
                      reinterpret_cast<void*>(candidate), midAddr - candidate,
                      b0, b1, b2, ok ? "PASS" : "fail");
            OutputDebugStringA(dbg);

            if (ok)
                return candidate;

            if (candidate < 16) break;
            candidate -= 16;
        }
    }

    // --- All strategies failed: dump bytes before match for diagnosis ---
    char hexDump[256] = {};
    for (int i = -32; i < 0; i++)
    {
        char byteStr[8];
        sprintf_s(byteStr, "%02x ", *reinterpret_cast<uint8_t*>(midAddr + i));
        strcat_s(hexDump, byteStr);
    }
    OutputDebugStringA(("[SharedDamage] FindFunctionStart failed. Bytes before match: " +
                        std::string(hexDump) + "\n").c_str());

    return 0;
}

// Resolve the local player's ChrStatModule* from the WorldChrManImp chain.
// Returns 0 if any link in the chain is null or causes an access violation.
// Used both in hkDamageFunc (for rcx comparison) and ReadLocalPlayerHp.
static uintptr_t GetLocalPlayerStatModule()
{
    __try
    {
        if (!g_worldChrManPtr) return 0;
        const uintptr_t wcm = *g_worldChrManPtr;
        if (!wcm) return 0;
        const uintptr_t arrayBase = *reinterpret_cast<uintptr_t*>(wcm + 0x10EF8);
        if (!arrayBase) return 0;
        const uintptr_t chrIns = *reinterpret_cast<uintptr_t*>(arrayBase);
        if (!chrIns) return 0;
        const uintptr_t moduleBag = *reinterpret_cast<uintptr_t*>(chrIns + 0x190);
        if (!moduleBag) return 0;
        const uintptr_t statModule = *reinterpret_cast<uintptr_t*>(moduleBag);
        return statModule; // may be 0 — caller checks
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugStringA("[SharedDamage] GetLocalPlayerStatModule: access violation caught\n");
        return 0;
    }
}

// Resolve the local player's ChrIns* — one step shallower than GetLocalPlayerStatModule.
// This is the object AddSpEffect expects as its first argument (rcx).
static uintptr_t GetLocalPlayerChrIns()
{
    __try
    {
        if (!g_worldChrManPtr) return 0;
        const uintptr_t wcm = *g_worldChrManPtr;
        if (!wcm) return 0;
        const uintptr_t arrayBase = *reinterpret_cast<uintptr_t*>(wcm + 0x10EF8);
        if (!arrayBase) return 0;
        return *reinterpret_cast<uintptr_t*>(arrayBase); // ChrIns* at slot 0
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

// Read the local player's current HP via the stat module.
// Returns -1 if the chain is not ready or an AV occurs.
static int32_t ReadLocalPlayerHp()
{
    const uintptr_t statModule = GetLocalPlayerStatModule();
    if (!statModule)
    {
        OutputDebugStringA("[SharedDamage] ReadLocalPlayerHp: statModule is null\n");
        ModUtils::Log("SharedDamage: ReadLocalPlayerHp: statModule is null");
        return -1;
    }
    return *reinterpret_cast<int32_t*>(statModule + 0x138);
}

// Thread ID of the thread that first invoked hkDamageFunc. MinHook calls our
// detour on the same thread the game used, so this is the authoritative
// game-thread ID. Written once; read by hkRunCallbacks for validation.
static std::atomic<DWORD> g_gameThreadId{0};

struct PendingDamageContext
{
    uintptr_t statModule = 0;
    int32_t   rawDamage  = 0;
    ULONGLONG tickMs     = 0;
    bool      active     = false;
};

static thread_local PendingDamageContext g_pendingDamage;
static constexpr ULONGLONG PENDING_DAMAGE_TTL_MS = 250;

static void DrainRemoteDamage(); // defined after ApplyDamageToLocalPlayer

static void ClearPendingDamageContext()
{
    g_pendingDamage = {};
}

static void CapturePendingRawDamage(uintptr_t statModule, int32_t rawDamage)
{
    g_pendingDamage.statModule = statModule;
    g_pendingDamage.rawDamage  = rawDamage;
    g_pendingDamage.tickMs     = GetTickCount64();
    g_pendingDamage.active     = true;

    char dbg[160];
    sprintf_s(dbg,
              "[SharedDamage] RawDamageCapture: statModule=%p rawDamage=%d\n",
              reinterpret_cast<void*>(statModule), rawDamage);
    OutputDebugStringA(dbg);
    ModUtils::Log("SharedDamage: RawDamageCapture: statModule=%p rawDamage=%d",
                  (void*)statModule, rawDamage);
}

static bool TryConsumePendingRawDamage(uintptr_t statModule, int32_t* outDamage)
{
    if (!g_pendingDamage.active)
        return false;

    const ULONGLONG ageMs = GetTickCount64() - g_pendingDamage.tickMs;

    if (g_pendingDamage.statModule != statModule ||
        g_pendingDamage.rawDamage <= 0 ||
        ageMs > PENDING_DAMAGE_TTL_MS)
    {
        char dbg[192];
        sprintf_s(dbg,
                  "[SharedDamage] PendingDamage stale/mismatch: raw=%d ctxStat=%p reqStat=%p ageMs=%llu\n",
                  g_pendingDamage.rawDamage,
                  reinterpret_cast<void*>(g_pendingDamage.statModule),
                  reinterpret_cast<void*>(statModule),
                  static_cast<unsigned long long>(ageMs));
        OutputDebugStringA(dbg);
        ModUtils::Log("SharedDamage: PendingDamage stale/mismatch: raw=%d ctxStat=%p reqStat=%p ageMs=%llu",
                      g_pendingDamage.rawDamage,
                      (void*)g_pendingDamage.statModule, (void*)statModule,
                      static_cast<unsigned long long>(ageMs));
        ClearPendingDamageContext();
        return false;
    }

    *outDamage = g_pendingDamage.rawDamage;
    ClearPendingDamageContext();
    return true;
}

void __fastcall hkDamageDeltaFunc(
    uintptr_t rcx, int32_t edx, uint8_t r8, uint8_t r9,
    float arg5, float arg6, uint8_t flagC
)
{
    const uintptr_t localStatModule = GetLocalPlayerStatModule();
    if (localStatModule && rcx == localStatModule && edx < 0)
    {
        const int64_t rawDamage64 = -static_cast<int64_t>(edx);
        if (rawDamage64 > 0 && rawDamage64 <= INT32_MAX)
            CapturePendingRawDamage(rcx, static_cast<int32_t>(rawDamage64));
    }

    fpDamageDeltaFunc(rcx, edx, r8, r9, arg5, arg6, flagC);
}

void __fastcall hkDamageFunc(uintptr_t rcx, int rdx)
{
    // Record the game thread ID on first invocation — MinHook calls us on the
    // same thread the game used, so this is more reliable than DllMain's TID.
    {
        DWORD expected = 0;
        g_gameThreadId.compare_exchange_strong(expected, GetCurrentThreadId(),
                                               std::memory_order_relaxed);
    }

    // Fast path: WorldChrManImp not ready yet.
    if (!g_worldChrManPtr || !*g_worldChrManPtr)
    {
        fpDamageFunc(rcx, rdx);
        return;
    }

    // Drain any damage queued by the poll thread — applied here on the game
    // thread so fpDamageFunc is never called from a background thread.
    DrainRemoteDamage();

    // rcx is the ChrStatModule* the game is writing new HP into.
    // Only act if it matches the local player's statModule.
    const uintptr_t localStatModule = GetLocalPlayerStatModule();
    if (!localStatModule || rcx != localStatModule)
    {
        fpDamageFunc(rcx, rdx);
        return;
    }

    // rdx is the new HP value. Confirm it's a damage event (HP decrease).
    const int32_t currentHp = *reinterpret_cast<int32_t*>(localStatModule + 0x138);
    const int32_t newHp     = rdx;
    int32_t pendingRawDamage = 0;
    const bool hasPendingRaw = TryConsumePendingRawDamage(localStatModule, &pendingRawDamage);

    if (hasPendingRaw && currentHp > 0 && newHp < currentHp)
    {
        ModUtils::Log("SharedDamage: Hook fired: using pending raw damage=%d (hp %d -> %d)",
                      pendingRawDamage, currentHp, newHp);
        fpDamageFunc(rcx, rdx);
        BroadcastDamage(pendingRawDamage);
    }
    else if (currentHp > 0 && newHp < currentHp)
    {
        // Fallback path: game writes currentHp - rawDamage directly, even when negative
        // (no sentinelization observed at the HP-write level). currentHp - newHp gives
        // the correct raw damage for both normal hits (newHp >= 0) and lethal overkill
        // (newHp < 0 because rawDamage > currentHp).
        // Guard: currentHp > 0 excludes post-death writes where currentHp is already 0;
        // those satisfy newHp < currentHp but must not generate additional packets.
        const int32_t damage = currentHp - newHp;
        ModUtils::Log("SharedDamage: Hook fired: %s damage=%d (hp %d -> %d)",
                      newHp < 0 ? "lethal" : "normal", damage, currentHp, newHp);
        fpDamageFunc(rcx, rdx);
        BroadcastDamage(damage);
    }
    else
    {
        // Either newHp >= currentHp (heal/restore) or currentHp == 0 (post-death write).
        if (hasPendingRaw)
        {
            ModUtils::Log("SharedDamage: Hook fired: pending raw damage=%d ignored because write was not a damage event (hp %d -> %d)",
                          pendingRawDamage, currentHp, newHp);
        }
        fpDamageFunc(rcx, rdx);
    }
}

// AoB scanner that returns 0 silently on failure instead of calling MessageBox.
// ModUtils::AobScan pops an MB_SYSTEMMODAL MessageBox when the pattern isn't
// found, which blocks the retry loop and requires the user to click OK each
// attempt. This replicates the same scan logic without the popup.
//
// Scans committed, readable memory regions starting from the eldenring.exe
// module base. Protection checks mirror ModUtils exactly so the same byte
// ranges are covered.
// startFrom: if non-zero, skip all bytes before this address. Used to iterate
// over multiple matches in the same pattern by passing prevMatch + 1 each time.
static uintptr_t SilentAobScan(const char* pattern, uintptr_t startFrom = 0)
{
    // Tokenize: space-separated, "?" is wildcard (ModUtils convention).
    std::vector<std::string> tokens;
    {
        std::istringstream iss(pattern);
        std::string tok;
        while (iss >> tok)
            tokens.push_back(tok);
    }
    if (tokens.empty()) return 0;

    const size_t len = tokens.size();

    // Try the named module first; fall back to GetModuleHandleA(nullptr) (always
    // returns the EXE base) in case me3 hasn't registered "eldenring.exe" yet.
    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleA("eldenring.exe"));
    if (!moduleBase)
    {
        OutputDebugStringA("[SharedDamage] GetModuleHandleA(eldenring.exe) returned NULL, falling back to GetModuleHandleA(nullptr)\n");
        moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    }
    if (!moduleBase) return 0;

    // Constrain scan to eldenring.exe's image only — avoids scanning 1600+ regions
    // of system DLLs, which are irrelevant and dramatically slow down each attempt.
    MODULEINFO modInfo{};
    GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(moduleBase),
                         &modInfo, sizeof(modInfo));
    const uintptr_t scanEnd = moduleBase + modInfo.SizeOfImage;

    // Start from the later of the module base or the caller's resume address.
    uintptr_t regionAddr = (startFrom > moduleBase) ? startFrom : moduleBase;

    MEMORY_BASIC_INFORMATION mbi{};
    while (VirtualQuery(reinterpret_cast<void*>(regionAddr), &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        // Stop once we've passed the end of the module image.
        if (reinterpret_cast<uintptr_t>(mbi.BaseAddress) >= scanEnd)
            break;
        const bool readable =
            mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_EXECUTE_READWRITE ||
             mbi.Protect == PAGE_READWRITE         ||
             mbi.Protect == PAGE_READONLY          ||
             mbi.Protect == PAGE_WRITECOPY         ||
             mbi.Protect == PAGE_EXECUTE_WRITECOPY ||
             mbi.Protect == PAGE_EXECUTE_READ);

        if (readable)
        {
            const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t end  = base + mbi.RegionSize;
            // Within the first region, honor startFrom so we don't re-find the
            // previous match. In subsequent regions base >= startFrom already.
            const uintptr_t scanStart = (startFrom > base) ? startFrom : base;

            for (uintptr_t cur = scanStart; cur + len <= end; ++cur)
            {
                bool match = true;
                for (size_t i = 0; i < len; ++i)
                {
                    if (tokens[i] == "?") continue;
                    if (*reinterpret_cast<const uint8_t*>(cur + i) !=
                        static_cast<uint8_t>(std::stoul(tokens[i], nullptr, 16)))
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return cur;
            }
        }

        regionAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return 0; // not found — no popup
}

// Phase 1: Spin until the AoB for the WorldChrManImp RIP-relative MOV is found
//          (i.e. Arxan has decrypted that region of .text).
// Phase 2: Spin until the object pointer itself is non-null (i.e. the game has
//          constructed the WorldChrManImp singleton and written it to .data).
// These are two separate waits: the static pointer address is fixed at link time,
// but the object it points to is created at game startup and may arrive late.
// Returns the address of the static pointer variable (not the object address).
static uintptr_t WaitForWorldChrMan()
{
    OutputDebugStringA("[SharedDamage] WaitForWorldChrMan entered\n");

    // --- Phase 1: find the static pointer address via AoB ---
    uintptr_t ptrAddr = 0;
    for (int attempt = 1; ; ++attempt)
    {
        // Try primary (MOV RAX, [rip+x]) then fallback (MOV RSI, [rip+x]).
        uintptr_t scan = SilentAobScan(WORLD_CHR_MAN_PATTERN);
        const char* patternUsed = "primary";
        if (!scan)
        {
            scan = SilentAobScan(WORLD_CHR_MAN_PATTERN_FALLBACK);
            patternUsed = "fallback";
        }
        if (scan)
        {
            // 48 8B 05/35 [rip+off32] — offset at +3, instruction size 7.
            ptrAddr = ModUtils::RelativeToAbsoluteAddress(scan + 3);
            char dbgMsg[192];
            sprintf_s(dbgMsg,
                      "[SharedDamage] WorldChrManImp static ptr at %p (via %s pattern, attempt %d)\n",
                      reinterpret_cast<void*>(ptrAddr), patternUsed, attempt);
            OutputDebugStringA(dbgMsg);
            ModUtils::Log("SharedDamage: WorldChrManImp static ptr at %p (via %s pattern, attempt %d)",
                          (void*)ptrAddr, patternUsed, attempt);
            break;
        }
        char dbgMsg[128];
        sprintf_s(dbgMsg, "[SharedDamage] WaitForWorldChrMan scan attempt %d\n", attempt);
        OutputDebugStringA(dbgMsg);
        ModUtils::Log("SharedDamage: WorldChrManImp not found (attempt %d), retrying in 2s...", attempt);
        Sleep(2000);
    }

    // --- Phase 2: wait for the game to populate the pointer with an object ---
    // The static pointer is valid but may still be null until the game constructs
    // the singleton. Cap at 60 attempts (2 minutes) to avoid hanging forever.
    for (int attempt = 1; attempt <= 60; ++attempt)
    {
        const uintptr_t value = *reinterpret_cast<uintptr_t*>(ptrAddr);
        char dbgMsg[192];
        sprintf_s(dbgMsg,
                  "[SharedDamage] Waiting for WorldChrManImp object... ptr=%p value=%p (attempt %d)\n",
                  reinterpret_cast<void*>(ptrAddr), reinterpret_cast<void*>(value), attempt);
        OutputDebugStringA(dbgMsg);
        ModUtils::Log("SharedDamage: Waiting for WorldChrManImp object... ptr=%p value=%p (attempt %d)",
                      (void*)ptrAddr, (void*)value, attempt);
        if (value)
        {
            OutputDebugStringA("[SharedDamage] WorldChrManImp object populated\n");
            ModUtils::Log("SharedDamage: WorldChrManImp object populated at %p", (void*)value);
            return ptrAddr;
        }
        Sleep(2000);
    }

    // Gave up waiting — return ptrAddr anyway so the caller can log which chain
    // stage is null (ReadLocalPlayerHp will catch it at wcm == 0).
    OutputDebugStringA("[SharedDamage] WorldChrManImp object never populated after 120s\n");
    ModUtils::Log("SharedDamage: WorldChrManImp object never populated after 120s — giving up.");
    return ptrAddr;
}

// --- Remote damage queue ---
// EnqueueRemoteDamage is called from the poll thread (ModThread).
// DrainRemoteDamage is called from two game-thread hooks:
//   1. hkDamageFunc — fires on any local HP write (fast path)
//   2. hkRunCallbacks — fires every time ersc/game calls SteamAPI_RunCallbacks
//      (reliable fallback that fires even when the local player is idle)
// Both drain points ensure fpDamageFunc is never called from ModThread.

static std::mutex           g_damageMutex;
static std::vector<int32_t> g_damagePending;

void EnqueueRemoteDamage(int32_t damage)
{
    std::lock_guard<std::mutex> lk(g_damageMutex);
    g_damagePending.push_back(damage);
}

static void DrainRemoteDamage()
{
    std::vector<int32_t> pending;
    {
        std::lock_guard<std::mutex> lk(g_damageMutex);
        pending.swap(g_damagePending);
    }
    for (const int32_t d : pending)
        ApplyDamageToLocalPlayer(d);
}

// Second drain point: hook SteamAPI_RunCallbacks so DrainRemoteDamage fires
// on the game/ersc thread every callback cycle, not just on HP-write events.
typedef void (*RunCallbacks_t)();
static RunCallbacks_t fpRunCallbacks = nullptr;

static void hkRunCallbacks()
{
    fpRunCallbacks();

    // Log each unique calling thread ID once. A set ensures no caller is
    // missed regardless of interleaving. Compare against g_gameThreadId
    // (captured from hkDamageFunc) — that's the authoritative game thread.
    {
        static std::mutex  s_seenMutex;
        static std::set<DWORD> s_seenThreads;
        const DWORD tid      = GetCurrentThreadId();
        const DWORD gameTid  = g_gameThreadId.load(std::memory_order_relaxed);
        bool isNew = false;
        {
            std::lock_guard<std::mutex> lk(s_seenMutex);
            isNew = s_seenThreads.insert(tid).second;
        }
        if (isNew)
        {
            char dbg[160];
            sprintf_s(dbg,
                      "[SharedDamage] hkRunCallbacks: tid=%lu gameTid=%lu isGameThread=%d\n",
                      tid, gameTid, (gameTid && tid == gameTid) ? 1 : 0);
            OutputDebugStringA(dbg);
            ModUtils::Log("SharedDamage: hkRunCallbacks: tid=%lu gameTid=%lu isGameThread=%d",
                          tid, gameTid, (gameTid && tid == gameTid) ? 1 : 0);
        }
    }

    DrainRemoteDamage();
}

// Apply a received damage amount to the local player via the hooked write path.
void ApplyDamageToLocalPlayer(int32_t damage)
{
    const uintptr_t statModule = GetLocalPlayerStatModule();
    if (!statModule)
    {
        OutputDebugStringA("[SharedDamage] ApplyDamageToLocalPlayer: statModule null — skipping\n");
        ModUtils::Log("SharedDamage: ApplyDamageToLocalPlayer: statModule null — skipping");
        return;
    }
    const int32_t currentHp = *reinterpret_cast<int32_t*>(statModule + 0x138);
    const int32_t newHp     = std::max(0, currentHp - damage);
    char dbg[128];
    sprintf_s(dbg, "[SharedDamage] ApplyDamageToLocalPlayer: damage=%d hp=%d -> %d\n",
              damage, currentHp, newHp);
    OutputDebugStringA(dbg);
    ModUtils::Log("SharedDamage: ApplyDamageToLocalPlayer: damage=%d hp=%d -> %d",
                  damage, currentHp, newHp);
    fpDamageFunc(statModule, newHp);
    ApplySharedHitSpEffectToLocalPlayer();
}


void ApplySharedHitSpEffectToLocalPlayer()
{
    if (!fpAddSpEffect)
    {
        OutputDebugStringA("[SharedDamage] ApplySharedHitSpEffectToLocalPlayer: fpAddSpEffect null — skipping\n");
        return;
    }
    const uintptr_t chrIns = GetLocalPlayerChrIns();
    if (!chrIns)
    {
        OutputDebugStringA("[SharedDamage] ApplySharedHitSpEffectToLocalPlayer: chrIns null — skipping\n");
        return;
    }
    char dbg[128];
    sprintf_s(dbg, "[SharedDamage] ApplySharedHitSpEffectToLocalPlayer: chrIns=%p spEffect=%d\n",
              reinterpret_cast<void*>(chrIns), SHARED_ON_HIT_SPEFFECT_ID);
    OutputDebugStringA(dbg);
    ModUtils::Log("SharedDamage: ApplySharedHitSpEffectToLocalPlayer: chrIns=%p spEffect=%d",
                  (void*)chrIns, SHARED_ON_HIT_SPEFFECT_ID);
    fpAddSpEffect(chrIns, SHARED_ON_HIT_SPEFFECT_ID, 1);
}

void InitHooks()
{
    OutputDebugStringA("[SharedDamage] InitHooks entered\n");
    // --- Wait for Arxan to finish decrypting before scanning ---
    g_worldChrManPtr = reinterpret_cast<uintptr_t*>(WaitForWorldChrMan());

    // --- Startup pointer-chain sanity check ---
    // Sleep briefly to give the game time to populate the player array, then
    // read local HP once. A -1 means an offset in the chain is wrong even before
    // any damage occurs; a plausible value (> 0) confirms the chain is correct.
    OutputDebugStringA("[SharedDamage] Waiting 5s for player array to populate...\n");
    ModUtils::Log("SharedDamage: Waiting 5s for player array to populate...");
    Sleep(5000);
    {
        const int32_t startupHp = ReadLocalPlayerHp();
        char dbg[128];
        sprintf_s(dbg, "[SharedDamage] Startup check: local player HP = %d\n", startupHp);
        OutputDebugStringA(dbg);
        ModUtils::Log("SharedDamage: Startup check: local player HP = %d", startupHp);
    }

    // --- Locate the damage function entry point ---
    //
    // Path A (preferred): scan directly for the confirmed prologue bytes.
    //   No backward walk needed — the match IS the function start.
    //
    // Path B (fallback): scan for a mid-function instruction and use
    //   FindFunctionStart to walk backward to the prologue. Applied only if
    //   the prologue pattern fails (e.g. after a game update changes the prolog).
    uintptr_t funcStart = 0;

    // --- Path A: direct prologue scan ---
    funcStart = SilentAobScan(DAMAGE_FUNC_PROLOGUE);
    if (funcStart)
    {
        char dbg[128];
        sprintf_s(dbg, "[SharedDamage] Damage function prologue found directly at %p\n",
                  reinterpret_cast<void*>(funcStart));
        OutputDebugStringA(dbg);
        ModUtils::Log("SharedDamage: Damage function prologue found directly at %p",
                      (void*)funcStart);

        // Verify the pattern is unique — a common prologue sequence may match
        // dozens of functions and we could be hooking the wrong one.
        int matchCount = 1;
        uintptr_t searchFrom = funcStart + 1;
        for (;;)
        {
            const uintptr_t next = SilentAobScan(DAMAGE_FUNC_PROLOGUE, searchFrom);
            if (!next) break;
            matchCount++;
            char warn[128];
            sprintf_s(warn,
                      "[SharedDamage] WARNING: prologue pattern not unique — match #%d at %p\n",
                      matchCount, reinterpret_cast<void*>(next));
            OutputDebugStringA(warn);
            ModUtils::Log("SharedDamage: WARNING: prologue pattern not unique — match #%d at %p",
                          matchCount, (void*)next);
            searchFrom = next + 1;
        }
        char summary[128];
        sprintf_s(summary, "[SharedDamage] Prologue pattern total matches: %d\n", matchCount);
        OutputDebugStringA(summary);
        ModUtils::Log("SharedDamage: Prologue pattern total matches: %d", matchCount);
    }

    // --- Path B: mid-instruction scan + backward prologue walk ---
    if (!funcStart)
    {
        OutputDebugStringA("[SharedDamage] Prologue pattern not found, trying mid-instruction fallback\n");
        ModUtils::Log("SharedDamage: Prologue pattern not found, trying mid-instruction fallback");

        struct { const char* pattern; const char* name; } damagePatterns[] = {
            { DAMAGE_PATTERN_LATE,  "late (1.10+)"    },
            { DAMAGE_PATTERN_EARLY, "early (pre-1.10)" },
        };

        uintptr_t midAddr   = 0;
        const char* patternUsed = nullptr;

        for (auto& dp : damagePatterns)
        {
            uintptr_t searchFrom = 0;
            for (;;)
            {
                const uintptr_t candidate = SilentAobScan(dp.pattern, searchFrom);
                if (!candidate) break;

                const uintptr_t prologue = FindFunctionStart(candidate);
                const size_t    offset   = prologue ? (candidate - prologue) : SIZE_MAX;

                if (prologue)
                {
                    const uint8_t b0 = *reinterpret_cast<const uint8_t*>(prologue);
                    const uint8_t b1 = *reinterpret_cast<const uint8_t*>(prologue + 1);
                    const uint8_t b2 = *reinterpret_cast<const uint8_t*>(prologue + 2);
                    char dbgBytes[128];
                    sprintf_s(dbgBytes,
                              "[SharedDamage] prologue bytes at %p: %02x %02x %02x\n",
                              reinterpret_cast<void*>(prologue), b0, b1, b2);
                    OutputDebugStringA(dbgBytes);
                    ModUtils::Log("SharedDamage: prologue bytes at %p: %02x %02x %02x",
                                  (void*)prologue, b0, b1, b2);
                }

                bool accepted = prologue && offset < 0x400;
                if (accepted && !LooksLikeProlog(prologue))
                {
                    char dbgFail[128];
                    sprintf_s(dbgFail,
                              "[SharedDamage] prologue at %p fails LooksLikeProlog — rejected\n",
                              reinterpret_cast<void*>(prologue));
                    OutputDebugStringA(dbgFail);
                    ModUtils::Log("SharedDamage: prologue at %p fails LooksLikeProlog — rejected",
                                  (void*)prologue);
                    accepted = false;
                }

                char dbg[256];
                sprintf_s(dbg,
                          "[SharedDamage] Damage pattern candidate at %p, prologue offset %zu — %s\n",
                          reinterpret_cast<void*>(candidate), offset, accepted ? "accepted" : "rejected");
                OutputDebugStringA(dbg);
                ModUtils::Log("SharedDamage: Damage pattern candidate at %p, prologue offset %zu — %s",
                              (void*)candidate, offset, accepted ? "accepted" : "rejected");

                if (accepted)
                {
                    midAddr     = candidate;
                    funcStart   = prologue;
                    patternUsed = dp.name;
                    break;
                }
                searchFrom = candidate + 1;
            }
            if (midAddr) break;
        }

        if (funcStart)
        {
            char dbg[192];
            sprintf_s(dbg, "[SharedDamage] Damage function found via %s pattern at %p\n",
                      patternUsed, reinterpret_cast<void*>(funcStart));
            OutputDebugStringA(dbg);
            ModUtils::Log("SharedDamage: Damage function found via %s pattern at %p",
                          patternUsed, (void*)funcStart);
        }
    }

    if (!funcStart)
    {
        ModUtils::Log("SharedDamage: Damage function not found — update patterns for this game version.");
        OutputDebugStringA("[SharedDamage] Damage function not found\n");
        return;
    }

    // --- Install hooks ---
    // --- Locate the generic HP-delta wrapper ---
    // This path sees a signed delta before the final HP write clamps/sentinelizes
    // lethal hits. We capture the raw incoming damage here and consume it from
    // hkDamageFunc once the write is confirmed.
    uintptr_t deltaFuncStart = 0;
    {
        const uintptr_t deltaMid = SilentAobScan(HP_DELTA_WRAPPER_PATTERN);
        if (deltaMid && deltaMid >= HP_DELTA_WRAPPER_BACKTRACK)
        {
            deltaFuncStart = deltaMid - HP_DELTA_WRAPPER_BACKTRACK;
            char dbg[160];
            sprintf_s(dbg,
                      "[SharedDamage] HP-delta wrapper found at %p (mid=%p)\n",
                      reinterpret_cast<void*>(deltaFuncStart),
                      reinterpret_cast<void*>(deltaMid));
            OutputDebugStringA(dbg);
            ModUtils::Log("SharedDamage: HP-delta wrapper found at %p (mid=%p)",
                          (void*)deltaFuncStart, (void*)deltaMid);

            int matchCount = 1;
            uintptr_t searchFrom = deltaMid + 1;
            for (;;)
            {
                const uintptr_t next = SilentAobScan(HP_DELTA_WRAPPER_PATTERN, searchFrom);
                if (!next) break;
                matchCount++;
                char warn[160];
                sprintf_s(warn,
                          "[SharedDamage] WARNING: HP-delta wrapper pattern not unique â€” match #%d at %p\n",
                          matchCount, reinterpret_cast<void*>(next));
                OutputDebugStringA(warn);
                ModUtils::Log("SharedDamage: WARNING: HP-delta wrapper pattern not unique â€” match #%d at %p",
                              matchCount, (void*)next);
                searchFrom = next + 1;
            }
            char summary[160];
            sprintf_s(summary,
                      "[SharedDamage] HP-delta wrapper pattern total matches: %d\n",
                      matchCount);
            OutputDebugStringA(summary);
            ModUtils::Log("SharedDamage: HP-delta wrapper pattern total matches: %d",
                          matchCount);
        }
        else
        {
            OutputDebugStringA("[SharedDamage] HP-delta wrapper pattern not found â€” lethal overkill will fall back to final HP deltas\n");
            ModUtils::Log("SharedDamage: HP-delta wrapper pattern not found â€” lethal overkill will fall back to final HP deltas");
        }
    }

    MH_Initialize();

    // Hook 1: game's HP-write function — primary drain point for remote damage.
    const MH_STATUS status = MH_CreateHook(
        reinterpret_cast<void*>(funcStart),
        reinterpret_cast<void*>(&hkDamageFunc),
        reinterpret_cast<void**>(&fpDamageFunc)
    );
    if (status != MH_OK)
    {
        ModUtils::Log("SharedDamage: MH_CreateHook (damage) failed (status %d).", (int)status);
        return;
    }
    ModUtils::Log("SharedDamage: Damage hook installed at %p.", (void*)funcStart);

    // Hook 2: generic HP-delta wrapper — captures raw incoming damage before
    // lethal writes collapse to a sentinel or to remaining HP.
    if (deltaFuncStart)
    {
        const MH_STATUS deltaStatus = MH_CreateHook(
            reinterpret_cast<void*>(deltaFuncStart),
            reinterpret_cast<void*>(&hkDamageDeltaFunc),
            reinterpret_cast<void**>(&fpDamageDeltaFunc)
        );
        if (deltaStatus != MH_OK)
        {
            ModUtils::Log("SharedDamage: MH_CreateHook (hp-delta) failed (status %d) — lethal overkill will fall back to final HP deltas.", (int)deltaStatus);
        }
        else
        {
            ModUtils::Log("SharedDamage: HP-delta hook installed at %p.", (void*)deltaFuncStart);
        }
    }

    // Hook 3: SteamAPI_RunCallbacks — reliable game-thread tick for draining
    // remote damage when the local player is idle and hkDamageFunc never fires.
    // ersc calls this from the game thread on every frame; our hook piggybacks.
    const MH_STATUS cbStatus = MH_CreateHookApi(
        L"steam_api64", "SteamAPI_RunCallbacks",
        reinterpret_cast<void*>(&hkRunCallbacks),
        reinterpret_cast<void**>(&fpRunCallbacks)
    );
    if (cbStatus != MH_OK)
    {
        ModUtils::Log("SharedDamage: MH_CreateHookApi (RunCallbacks) failed (status %d) — remote damage will drain on HP-write only.", (int)cbStatus);
    }
    else
    {
        ModUtils::Log("SharedDamage: SteamAPI_RunCallbacks hook installed.");
    }

    MH_EnableHook(MH_ALL_HOOKS);

    // --- Locate AddSpEffect ---
    // Pattern matches mid-function; subtract 0x1D to reach the prologue.
    // Source: The Grand Archives Elden Ring CT-TGA SpEffect_code.cea
    {
        const uintptr_t spEffectMid = SilentAobScan(ADD_SPEFFECT_PATTERN);
        if (spEffectMid)
        {
            fpAddSpEffect = reinterpret_cast<AddSpEffect_t>(spEffectMid - 0x1D);
            char dbg[128];
            sprintf_s(dbg, "[SharedDamage] AddSpEffect found at %p (mid=%p)\n",
                      reinterpret_cast<void*>(fpAddSpEffect),
                      reinterpret_cast<void*>(spEffectMid));
            OutputDebugStringA(dbg);
            ModUtils::Log("SharedDamage: AddSpEffect found at %p (mid=%p)",
                          (void*)fpAddSpEffect, (void*)spEffectMid);

            // Verify uniqueness — a duplicate would mean we hooked the wrong function.
            int matchCount = 1;
            uintptr_t searchFrom = spEffectMid + 1;
            for (;;)
            {
                const uintptr_t next = SilentAobScan(ADD_SPEFFECT_PATTERN, searchFrom);
                if (!next) break;
                matchCount++;
                char warn[128];
                sprintf_s(warn,
                          "[SharedDamage] WARNING: AddSpEffect pattern not unique — match #%d at %p\n",
                          matchCount, reinterpret_cast<void*>(next));
                OutputDebugStringA(warn);
                ModUtils::Log("SharedDamage: WARNING: AddSpEffect pattern not unique — match #%d at %p",
                              matchCount, (void*)next);
                searchFrom = next + 1;
            }
            char summary[128];
            sprintf_s(summary, "[SharedDamage] AddSpEffect pattern total matches: %d\n", matchCount);
            OutputDebugStringA(summary);
            ModUtils::Log("SharedDamage: AddSpEffect pattern total matches: %d", matchCount);
        }
        else
        {
            OutputDebugStringA("[SharedDamage] AddSpEffect pattern not found — SpEffect will not be applied\n");
            ModUtils::Log("SharedDamage: AddSpEffect pattern not found — SpEffect will not be applied on receive");
        }
    }

    OutputDebugStringA("[SharedDamage] InitHooks returning\n");
    ModUtils::Log("SharedDamage: InitHooks returning");
}

void ShutdownHooks()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_worldChrManPtr = nullptr;
}
