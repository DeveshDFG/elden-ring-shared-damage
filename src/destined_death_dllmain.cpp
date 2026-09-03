#include <windows.h>

#include "destined_death_hooks.h"
#include "param_patch.h"

static DWORD WINAPI DestinedDeathWorker(LPVOID)
{
    if (!IsSupportedDestinedDeathExecutable())
        return 0;

    if (!InitDestinedDeathHooks())
        return 0;

    InitDestinedDeathParamPatch();
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
