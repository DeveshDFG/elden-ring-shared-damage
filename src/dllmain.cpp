#include <windows.h>
#include "hooks.h"
#include "damage.h"
#include "param_patch.h"
#include <fstream>
#include "ModUtils.h"
#include <steam/steam_api.h>

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
    InitRuntimeParamPatch();

    // Poll for incoming damage packets on this thread for the lifetime of the DLL.
    // A second thread caused loader-lock contention (DLL_THREAD_ATTACH had to fire
    // for every thread spawn while the game held the lock). ModThread is already the
    // one long-lived mod thread — polling here is the standard pattern.
    {
        char dbg[128];
        sprintf_s(dbg, "[SharedDamage] P2P poll loop starting — channel=%d magic=0x%08X\n",
                  DAMAGE_CHANNEL, DAMAGE_PACKET_MAGIC);
        OutputDebugStringA(dbg);
        ModUtils::Log("SharedDamage: P2P poll loop starting — channel=%d magic=0x%08X",
                      DAMAGE_CHANNEL, DAMAGE_PACKET_MAGIC);
    }
    while (true)
    {
        Sleep(1);
        ISteamNetworkingMessages* msgs = SteamNetworkingMessages();
        if (!msgs) continue;
        SteamNetworkingMessage_t* incoming[16];
        const int count = msgs->ReceiveMessagesOnChannel(DAMAGE_CHANNEL, incoming, 16);
        for (int i = 0; i < count; i++)
        {
            SteamNetworkingMessage_t* msg = incoming[i];
            char dbg[256];
            sprintf_s(dbg,
                      "[SharedDamage] ReceiveMsg: size=%d from=%llu\n",
                      msg->m_cbSize, msg->m_identityPeer.GetSteamID64());
            OutputDebugStringA(dbg);
            ModUtils::Log("SharedDamage: ReceiveMsg: size=%d from=%I64u",
                          msg->m_cbSize, msg->m_identityPeer.GetSteamID64());

            if (msg->m_cbSize == sizeof(DamagePacket))
            {
                const DamagePacket* pkt = reinterpret_cast<const DamagePacket*>(msg->m_pData);
                if (pkt->magic == DAMAGE_PACKET_MAGIC)
                    EnqueueRemoteDamage(pkt->damage);
            }
            msg->Release();
        }
    }
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
