#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "LicenseCollection.h"

#include "CPUID.h"
#include "DisplayAdapter.h"
#include "Disk.h"
#include "GPUAdapter.h"
#include "Imports.h"

#include <cstdint>

const CollectedFingerprints& CollectBuildTimeFingerprints()
{
    static bool init = false;
    static CollectedFingerprints cf;
    if (init) return cf;

    cf.CPUIDAndKUser = GetObfFingerprint();

#ifdef _WIN32
    cf.GPU.DXGI = ComputeDXGIFp();
    if (cf.GPU.DXGI) cf.GPU.HaveMask |= OfMaskDXGI;
    cf.GPU.D3D11 = ComputeD3DxFp(false);
    if (cf.GPU.D3D11) cf.GPU.HaveMask |= OfMaskD3D11;
    cf.GPU.D3D12 = ComputeD3DxFp(true);
    if (cf.GPU.D3D12) cf.GPU.HaveMask |= OfMaskD3D12;

    cf.GPU.GDI = ComputeGDIFp();
    if (cf.GPU.GDI) cf.GPU.HaveMask |= OfMaskGDI;
    cf.GPU.User32 = ComputeUser32Fp();
    if (cf.GPU.User32) cf.GPU.HaveMask |= OfMaskUser32;
    cf.GPU.Display = ComputeDisplayFp();
    if (cf.GPU.Display) cf.GPU.HaveMask |= OfMaskDisplay;

    cf.GPU.DiskPool = ComputeDiskObfPool();
    if (!cf.GPU.DiskPool.empty())
    {
        cf.GPU.DiskBuckets = cf.GPU.DiskPool.front();
        uint64_t h = FNVInit;
        h = FNVFoldU32(h, (uint32_t)cf.GPU.DiskBuckets.CandidateIdx);
        h = FNVFoldU32(h, (uint32_t)DiskCenterBucket);
        cf.GPU.Disk = SentinelSafe(h);
        cf.GPU.HaveMask |= OfMaskDisk;
    }
#endif

    init = true;
    return cf;
}