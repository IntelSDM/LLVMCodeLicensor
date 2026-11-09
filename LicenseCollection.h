#pragma once

#include "CPUID.h"
#include "GPUAdapter.h"

struct CollectedFingerprints
{
    HwFingerprint CPUIDAndKUser;
    ObfGPUFp GPU;
};

const CollectedFingerprints& CollectBuildTimeFingerprints();