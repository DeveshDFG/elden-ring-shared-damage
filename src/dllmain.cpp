#include <windows.h>

#include "damage.h"
#include "hooks.h"
#include "shared_damage_boss_diag.h"

#include <steam/steam_api.h>

static DWORD WINAPI ModThread(LPVOID)
{
    InitSharedDamageBossDiag();
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
            const uint64_t senderSteamId =
                message->m_identityPeer.GetSteamID64();

            if (messageSize != sizeof(DamagePacket))
            {
                SharedDamageBossDiagTryLogReceive(
                    messageSize,
                    senderSteamId,
                    false,
                    "size-mismatch",
                    0);
                message->Release();
                continue;
            }

            const auto* packet =
                reinterpret_cast<const DamagePacket*>(message->m_pData);
            if (packet->magic != DAMAGE_PACKET_MAGIC)
            {
                SharedDamageBossDiagTryLogReceive(
                    messageSize,
                    senderSteamId,
                    false,
                    "magic-mismatch",
                    packet->damage);
                message->Release();
                continue;
            }

            if (packet->damage <= 0)
            {
                SharedDamageBossDiagTryLogReceive(
                    messageSize,
                    senderSteamId,
                    false,
                    "nonpositive-damage",
                    packet->damage);
                message->Release();
                continue;
            }

            SharedDamageBossDiagTryLogReceive(
                messageSize,
                senderSteamId,
                true,
                "accepted",
                packet->damage);
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
