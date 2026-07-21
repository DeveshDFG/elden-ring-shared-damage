#include <windows.h>

#include "damage.h"
#include "hooks.h"

#include <steam/steam_api.h>

static DWORD WINAPI ModThread(LPVOID)
{
    InitHooks();

    while (true)
    {
        Sleep(5);

        ISteamNetworkingMessages* messages = SteamNetworkingMessages();
        if (!messages)
            continue;

        SteamNetworkingMessage_t* incoming[16]{};
        const int count =
            messages->ReceiveMessagesOnChannel(DAMAGE_CHANNEL, incoming, 16);
        for (int i = 0; i < count; ++i)
        {
            SteamNetworkingMessage_t* message = incoming[i];
            const int messageSize = message->m_cbSize;

            if (messageSize != sizeof(DamagePacket))
            {
                message->Release();
                continue;
            }

            const auto* packet =
                reinterpret_cast<const DamagePacket*>(message->m_pData);
            if (packet->magic != DAMAGE_PACKET_MAGIC)
            {
                message->Release();
                continue;
            }

            if (packet->damage <= 0)
            {
                message->Release();
                continue;
            }

            EnqueueRemoteDamage(packet->damage);
            message->Release();
        }
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        if (HANDLE thread = CreateThread(nullptr, 0, ModThread, nullptr, 0, nullptr))
            CloseHandle(thread);
    }
    return TRUE;
}
