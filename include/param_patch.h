#pragma once

// Patch live game params in memory so NPC attacks locally apply the destined
// death effect without requiring an edited regulation.bin on disk.
void InitRuntimeParamPatch();
