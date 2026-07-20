#include <windows.h>

#include "destined_death_hooks.h"
#include "param_patch.h"

static DWORD WINAPI DestinedDeathWorker(LPVOID)
{
    InitDestinedDeathParamPatch();
    InitDestinedDeathHooks();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        if (HANDLE thread =
                CreateThread(nullptr, 0, DestinedDeathWorker, nullptr, 0, nullptr))
            CloseHandle(thread);
    }
    return TRUE;
}
