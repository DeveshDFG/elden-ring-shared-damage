# Elden Ring Shared Damage and Destined Death

This repository builds two independently loadable Elden Ring DLL mods. They can run separately or together through Mod engine 3 (highly recommend) or Mod engine 2.

## DLLs

### `elden-ring-shared-damage.dll`

Shares confirmed HP damage between players in the same Seamless Co-op world.
When one player takes damage, the exact raw damage is sent to the other Steam lobby members and applied through the game's HP-write function.

- Healing is not shared.
- Maximum HP is not synchronized.
- Each player keeps their own current and maximum HP.
- Only confirmed local HP damage is broadcast.

#### Damage provenance

A damage packet is created only when all of the following are true:

1. A negative HP delta was captured for the local player's stat module.
2. The pending delta is consumed by the matching final HP write within a 250 ms window.
3. The final write decreases HP.
4. The player is confirmed to be in the same world as at least one remote player.

HP decreases without matching attack-damage provenance still occur locally but are not shared.

#### Same-world and loading protection

Same-world state is derived from one coherent WorldChrMan/NetPlayers snapshot per Steam callback cycle:

- Slot 0 resolves the current local player and stat module (host).
- Slots 1-5 are the production remote-player slots (guests).
- A valid remote slot activates shared damage.
- A valid snapshot with no remote players deactivates it.
- An unavailable snapshot is treated as an unknown/loading state and preserves the last confirmed latch instead of forcing a false transition.
- Inbound damage is applied only with the local stat module resolved by the current snapshot.

These rules keep sharing active throughout the world while preventing damage taken during teleports and disconnected guests from continuing to share damage to the host in their own world.

#### Networking

Damage packets use Steam Networking Messages. The DLL tracks the Seamless Co-op Steam lobby, sends to every other valid lobby member, polls incoming packets on its mod thread, validates packet size/damage, and queues accepted damage for application on the game thread.

Dependencies:

- MinHook
- Steamworks SDK headers and `steam_api64.lib` at build time
- Steam/Seamless Co-op at runtime

### `elden-ring-destined-death.dll`

Uses libER runtime params and a MinHook SpEffect hook to make successful NPC attacks apply custom Destined Death SpEffect `90061` without requiring an edited `regulation.bin` (able to use other regulation.bin mods with this).

At startup it:

- Clones `SpEffectParam[29521]` onto `SpEffectParam[90061]` (Destined Death).
- Applies the custom icon, duration, max-HP reduction, VFX, lifecycle, target, and bonfire-recovery overrides.
- Writes `90061` to `AtkParam_Npc.spEffectId3`, preserving the 35 excluded NPC attack rows in `src/param_patch.cpp`.
- Does not patch `AtkParam_Pc`.
- Generates a sorted 6,119-row bullet allowlist from `Bullet.csv` during the build.
- Writes `90061` to `Bullet.spEffectId3` only for rows whose `atkId_Bullet` resolves to an NPC attack with positive HP-damage potential.
- Does not patch player-only bullets outside the curated NPC allowlist.

#### Deflecting Hardtear exemption

The DLL hooks the validated inner ChrIns SpEffect application routine. A new `90061` (Destined Death) application is suppressed only when the same target currently has active SpEffect `102001` (aka a deflect).

- Ordinary blocks still receive the Destined Death effect.
- Failed deflects still receive the Destined Death effect.
- Having the tear active without a successful deflect still receives the Destined Death effect.
- Existing Destined Death instances are not removed, cleansed, or shortened.
- Invalid target/effect-list reads fail open and forward the application.

Dependencies:

- libER
- MinHook

## Build requirements

- CMake 3.21 or newer
- Visual Studio 2022 with the Desktop development with C++ workload
- An x64 generator/toolchain
- Steamworks SDK when building Shared Damage
- Python 3 and libER when building Destined Death

Both targets are enabled by default:

- `BUILD_SHARED_DAMAGE_MOD`
- `BUILD_DESTINED_DEATH_MOD`

MinHook is fetched through CMake. For Destined Death, CMake uses `libER/libER` when present and otherwise fetches the pinned libER revision.

### Build both DLLs

```powershell
cmake -B build -A x64 -G "Visual Studio 17 2022" `
  -DSTEAM_SDK_PATH=C:/Steam/steamworks_sdk/sdk
cmake --build build --config Release
```

Outputs:

```text
natives/elden-ring-shared-damage.dll
natives/elden-ring-destined-death.dll
```

The Destined Death pre-build step regenerates:

```text
include/bullet_sp_effect_allowlist_generated.h
```

from `Bullet.csv` using `tools/generate_bullet_allowlist.py`.

### Build Shared Damage only

```powershell
cmake -B build -A x64 -G "Visual Studio 17 2022" `
  -DBUILD_DESTINED_DEATH_MOD=OFF `
  -DSTEAM_SDK_PATH=C:/Steam/steamworks_sdk/sdk
cmake --build build --config Release
```

This configuration does not require libER or Python.

### Build Destined Death only

```powershell
cmake -B build -A x64 -G "Visual Studio 17 2022" `
  -DBUILD_SHARED_DAMAGE_MOD=OFF
cmake --build build --config Release
```

This configuration does not require the Steamworks SDK.

## Source layout

Shared Damage:

```text
src/dllmain.cpp
src/hooks.cpp
src/damage.cpp
```

Destined Death:

```text
src/destined_death_dllmain.cpp
src/destined_death_hooks.cpp
src/param_patch.cpp
```

## Pattern maintenance

The hook signatures and expected RVAs in `src/hooks.cpp` and `src/destined_death_hooks.cpp` are specific to the tested Elden Ring version 1.16.2. After a game update, reacquire unique AoB matches, expected function-entry/pdata validation, and successful MinHook installation before reenabling the mod.
