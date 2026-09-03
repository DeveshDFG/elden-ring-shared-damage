#pragma once

// Patch live game params in memory so NPC attacks and allowlisted bullets locally
// apply the destined death effect without requiring an edited regulation.bin on disk.
// Returns true only after the intended runtime patches complete.
bool InitDestinedDeathParamPatch();
