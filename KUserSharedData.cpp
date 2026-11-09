#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "KUserSharedData.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace llvm;

const KUserSpec KUserPool[] =
{
    { 0x0260, "KUSD.NtBuildNumber",    true  },
    { 0x026C, "KUSD.NtMajorVersion",   false },
    { 0x0270, "KUSD.NtMinorVersion",   true  },
    { 0x0268, "KUSD.ProductType+Arch", false },
    { 0x02D4, "KUSD.KdDbg+MitPol",     true  },
    { 0x02E8, "KUSD.PhysicalPages",    false },
    { 0x02F0, "KUSD.SharedDataFlags",  true  },
    { 0x0244, "KUSD.LargePageMin",     false },
};
const unsigned KUserPoolSize = sizeof(KUserPool) / sizeof(KUserPool[0]);

static std::mt19937& GetPRNG()
{
    static std::mt19937 g([]()
    {
        std::random_device rd;
        return (unsigned)(rd() ^ (unsigned)std::chrono::high_resolution_clock::now().time_since_epoch().count());
    }());
    return g;
}

void ReadKUserFields(uint32_t* out)
{
#ifdef _WIN32
    for (unsigned i = 0; i < KUserPoolSize; ++i)
    {
        const volatile uint32_t* p = reinterpret_cast<const volatile uint32_t*>(KUserBase + (uintptr_t)KUserPool[i].Offset);
        out[i] = *p;
    }
#else
    for (unsigned i = 0; i < KUserPoolSize; ++i) out[i] = 0;
#endif
}

std::vector<unsigned> PickKUserFields(unsigned k)
{
    if (k == 0) return {};
    if (k > KUserPoolSize) k = KUserPoolSize;
    std::vector<unsigned> all;
    all.reserve(KUserPoolSize);
    for (unsigned i = 0; i < KUserPoolSize; ++i) all.push_back(i);
    std::shuffle(all.begin(), all.end(), GetPRNG());
    return std::vector<unsigned>(all.begin(), all.begin() + k);
}

void AppendKUserAsmSnippet(std::string& asmtmpl, ArrayRef<unsigned> kuseridxs)
{
    char buf[160];
    for (unsigned idx : kuseridxs)
    {
        const KUserSpec& ks = KUserPool[idx];
        std::snprintf(buf, sizeof(buf), "mov r14d, dword ptr ds:[0x%08x]\n\t", (unsigned)(KUserBase + ks.Offset));
        asmtmpl += buf;
        asmtmpl += ks.ToHi ? "xor r12d, r14d\n\t" : "xor r13d, r14d\n\t";
    }
}

void FoldKUserIntoKey(const uint32_t* kusdvalues, ArrayRef<unsigned> kuseridxs, uint32_t& hiraw, uint32_t& loraw)
{
    for (unsigned idx : kuseridxs)
    {
        if (KUserPool[idx].ToHi) hiraw ^= kusdvalues[idx];
        else loraw ^= kusdvalues[idx];
    }
}