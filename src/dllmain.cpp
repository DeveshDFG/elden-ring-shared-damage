#include <windows.h>
#include "hooks.h"
#include <fstream>
#include "ModUtils.h"

static DWORD WINAPI ModThread(LPVOID lpParam)
{
    OutputDebugStringA("[SharedDamage] ModThread started\n");

    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);
    char cwdMsg[MAX_PATH + 64];
    sprintf_s(cwdMsg, "[SharedDamage] CWD = %s\n", cwd);
    OutputDebugStringA(cwdMsg);

    // Log file will be written to: CWD\mods\elden-ring-shared-damage\log.txt
    ModUtils::Log("SharedDamage: ModThread started");

    OutputDebugStringA("[SharedDamage] Calling InitHooks\n");
    InitHooks();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    OutputDebugStringA("[SharedDamage] DllMain called\n");

    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        OutputDebugStringA("[SharedDamage] DLL loaded, built: " __DATE__ " " __TIME__ "\n");
        OutputDebugStringA("[SharedDamage] DLL_PROCESS_ATTACH\n");
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, ModThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
