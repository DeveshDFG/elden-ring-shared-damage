#include <windows.h>
#include "hooks.h"
#include "ModUtils.h"

static DWORD WINAPI ModThread(LPVOID lpParam)
{
    ModUtils::Initialize("EldenRingSharedDamage");
    InitHooks();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, ModThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
