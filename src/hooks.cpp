#include "hooks.h"
#include "damage.h"
#include "ModUtils.h"
#include <MinHook.h>
#include <cstdint>

// WorldChrManImp pointer pattern — RIP-relative MOV, double-dereference.
// Scan returns address of the instruction; the 4-byte RIP offset sits at +3,
// instruction size is 7. RelativeToAbsoluteAddress(scan + 3) yields the address
// of the game's static WorldChrManImp* variable.
// Source: veeenu/eldenring-practice-tool, samjviana/souls_vision
static const char* WORLD_CHR_MAN_PATTERN =
    "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0F 48 39 88";

// These patterns locate an instruction WITHIN the damage function, not its entry
// point. FindFunctionStart() scans backward from the match to find the actual
// function prologue before handing the address to MinHook.
//
// Try the 1.10+ pattern first; fall back to the earlier one.
// If both fail after a game update, open eldenring.exe in IDA/Ghidra, locate the
// function containing these bytes, and derive a new AoB from its first instruction.
// Source: kh0nsu/FromAobScan
static const char* DAMAGE_PATTERN_LATE =
    "29 43 08 83 7B 08 00 89 83 ?? ?? 00 00 7F ?? 80 BB ?? ?? 00 00 00 75 ??";
static const char* DAMAGE_PATTERN_EARLY =
    "89 4B 08 48 85 F6 74 ?? 48 8D 54 24 ?? 48 8B CE E8 ?? ?? ?? ?? EB ??";

// Address of the game's WorldChrManImp* static variable.
// Dereference at hook time to get the live instance pointer.
uintptr_t* g_worldChrManPtr = nullptr;

// Generic typedef — we never read the function's arguments because we detect
// damage via the local player's HP delta, so the true signature doesn't matter.
typedef void(__fastcall* DamageFunc_t)();
static DamageFunc_t fpDamageFunc = nullptr;

// Scan backward from a mid-function address to find the enclosing function's
// entry point. MSVC x64 pads between functions with 0xCC (INT3) bytes, so the
// first non-CC byte after a CC run is the function prologue. We verify that the
// candidate bytes match a common x64 MSVC prologue pattern before trusting it.
// Returns 0 if no suitable start is found within MAX_BACK bytes.
static uintptr_t FindFunctionStart(uintptr_t midAddr)
{
    static const uintptr_t MAX_BACK = 0x300; // 768 bytes — generous for large funcs

    for (uintptr_t p = midAddr - 1; p > midAddr - MAX_BACK; p--)
    {
        if (*reinterpret_cast<uint8_t*>(p) != 0xCC)
            continue;

        // Skip any run of consecutive CC bytes (common for 16-byte alignment pads).
        uintptr_t candidate = p + 1;
        while (*reinterpret_cast<uint8_t*>(candidate) == 0xCC)
            candidate++;

        // Guard: don't accept a candidate that's past our original address.
        if (candidate >= midAddr)
            break;

        const uint8_t b0 = *reinterpret_cast<uint8_t*>(candidate);
        const uint8_t b1 = *reinterpret_cast<uint8_t*>(candidate + 1);
        const uint8_t b2 = *reinterpret_cast<uint8_t*>(candidate + 2);

        // Common MSVC x64 function prologues:
        //   40/41 + 5X       — REX PUSH  (push rbx/rbp/rsi/rdi/r12-r15)
        //   48 83 EC xx      — SUB RSP, imm8
        //   48 89 XX 24      — MOV [RSP+imm], reg  (spill of incoming arg)
        //   55               — PUSH RBP
        //   53               — PUSH RBX  (no REX, common for smaller functions)
        const bool looksLikeProlog =
            ((b0 == 0x40 || b0 == 0x41) && (b1 >= 0x50 && b1 <= 0x57)) || // REX PUSH
            (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) ||                    // SUB RSP, imm8
            (b0 == 0x48 && b1 == 0x89 && (b2 == 0x4C || b2 == 0x54 ||
                                           b2 == 0x5C || b2 == 0x74 ||
                                           b2 == 0x7C)) ||                  // MOV [RSP+x], reg
            (b0 == 0x55) ||                                                  // PUSH RBP
            (b0 == 0x53);                                                    // PUSH RBX

        if (looksLikeProlog)
            return candidate;
    }

    return 0;
}

// Walk the pointer chain to read the local player's current HP.
// Returns -1 if any pointer in the chain is null.
static int32_t ReadLocalPlayerHp()
{
    if (!g_worldChrManPtr) return -1;
    const uintptr_t wcm = *g_worldChrManPtr;
    if (!wcm) return -1;

    // WorldChrManImp + 0x10EF8 → pointer to Entry[6] array base
    const uintptr_t arrayBase = *reinterpret_cast<uintptr_t*>(wcm + 0x10EF8);
    if (!arrayBase) return -1;

    // Entry[0].chrIns — local player (Entry stride = 16 bytes)
    const uintptr_t chrIns = *reinterpret_cast<uintptr_t*>(arrayBase);
    if (!chrIns) return -1;

    // ChrIns + 0x190 → ChrModuleBag*
    const uintptr_t moduleBag = *reinterpret_cast<uintptr_t*>(chrIns + 0x190);
    if (!moduleBag) return -1;

    // ChrModuleBag + 0x0 → ChrStatModule*
    const uintptr_t statModule = *reinterpret_cast<uintptr_t*>(moduleBag);
    if (!statModule) return -1;

    // ChrStatModule + 0x138 → int32_t hp
    return *reinterpret_cast<int32_t*>(statModule + 0x138);
}

void __fastcall hkDamageFunc()
{
    const int32_t oldHp = ReadLocalPlayerHp();

    fpDamageFunc(); // call through MinHook trampoline — runs full original function

    const int32_t newHp = ReadLocalPlayerHp();

    // A valid damage event: HP was positive and dropped.
    if (oldHp > 0 && newHp >= 0 && newHp < oldHp)
        PropagateDamage(oldHp - newHp);
}

void InitHooks()
{
    // --- Resolve WorldChrManImp ---
    const uintptr_t wcmScan = ModUtils::AobScan(WORLD_CHR_MAN_PATTERN);
    if (!wcmScan)
    {
        ModUtils::Log("SharedDamage: WorldChrManImp pattern not found.");
        return;
    }
    // Instruction: 48 8B 05 [rip+off32] — offset at +3, instruction size 7.
    uintptr_t wcmPtrAddr = ModUtils::RelativeToAbsoluteAddress(wcmScan + 3);
    g_worldChrManPtr = reinterpret_cast<uintptr_t*>(wcmPtrAddr);
    ModUtils::Log("SharedDamage: WorldChrManImp ptr resolved at %p", (void*)wcmPtrAddr);

    // --- Locate damage AoB match ---
    uintptr_t midAddr = ModUtils::AobScan(DAMAGE_PATTERN_LATE);
    const char* patternUsed = "late (1.10+)";
    if (!midAddr)
    {
        midAddr = ModUtils::AobScan(DAMAGE_PATTERN_EARLY);
        patternUsed = "early (pre-1.10)";
    }
    if (!midAddr)
    {
        ModUtils::Log("SharedDamage: Damage pattern not found — update patterns for this game version.");
        return;
    }
    ModUtils::Log("SharedDamage: Damage instruction found at %p (%s pattern)", (void*)midAddr, patternUsed);

    // --- Walk backward to the enclosing function's prologue ---
    // Hooking at the function entry (not mid-function) lets MinHook build a
    // correct trampoline and avoids stack-frame corruption in our hook callback.
    const uintptr_t funcStart = FindFunctionStart(midAddr);
    if (!funcStart)
    {
        ModUtils::Log("SharedDamage: Could not find function prologue from instruction at %p. "
                      "Locate the enclosing function in IDA/Ghidra and derive a prologue-targeted AoB.",
                      (void*)midAddr);
        return;
    }
    ModUtils::Log("SharedDamage: Function prologue found at %p (offset -%zu from pattern)",
                  (void*)funcStart, midAddr - funcStart);

    // --- Install hook at function entry ---
    MH_Initialize();
    const MH_STATUS status = MH_CreateHook(
        reinterpret_cast<void*>(funcStart),
        reinterpret_cast<void*>(&hkDamageFunc),
        reinterpret_cast<void**>(&fpDamageFunc)
    );
    if (status != MH_OK)
    {
        ModUtils::Log("SharedDamage: MH_CreateHook failed (status %d).", (int)status);
        return;
    }
    MH_EnableHook(MH_ALL_HOOKS);
    ModUtils::Log("SharedDamage: Hook installed at function entry %p.", (void*)funcStart);
}

void ShutdownHooks()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_worldChrManPtr = nullptr;
}
