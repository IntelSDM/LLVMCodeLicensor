#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "CPUID.h"
#include "KUserSharedData.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#endif

using namespace llvm;

const LeafSpec CPUIDPool[] =
{
    { 0x00000001u, 0u, true,  "0x1",         false },
    { 0x40000003u, 0u, false, "0x40000003",  true  },
    { 0x40000006u, 0u, false, "0x40000006",  true  },
    { 0x80000002u, 0u, false, "0x80000002",  false },
    { 0x80000003u, 0u, false, "0x80000003",  false },
    { 0x80000004u, 0u, false, "0x80000004",  false },
    { 0x80000008u, 0u, false, "0x80000008",  false },
};
const unsigned CPUIDPoolSize = sizeof(CPUIDPool) / sizeof(CPUIDPool[0]);

const MiscProbeSpec MiscProbePool[] =
{
    { MiscProbeKind::XGetBV, 0xFFFFFFFFu, true,  "xgetbv.xcr0" },
    { MiscProbeKind::SMSW,   0xE0010037u, false, "smsw.cr0"    },
};
const unsigned MiscProbePoolSize = sizeof(MiscProbePool) / sizeof(MiscProbePool[0]);

static_assert(sizeof(CPUIDPool) / sizeof(CPUIDPool[0]) <= LICENSING_CPUID_POOL_MAX, "CPUID pool larger than HwFingerprint storage");
static_assert(sizeof(MiscProbePool) / sizeof(MiscProbePool[0]) <= LICENSING_MISC_POOL_MAX, "Misc-probe pool larger than HwFingerprint storage");

static std::mt19937& GetPRNG()
{
    static std::mt19937 g([]()
    {
        std::random_device rd;
        return (unsigned)(rd() ^ (unsigned)std::chrono::high_resolution_clock::now().time_since_epoch().count());
    }());
    return g;
}

static uint64_t ReadXCR0()
{
#ifdef _WIN32
    return _xgetbv(0);
#else
    return 0;
#endif
}

static uint64_t ReadCR0ViaSMSW()
{
    return 0x80010033ULL;
}

HwFingerprint GetObfFingerprint()
{
    static bool init = false;
    static HwFingerprint f = {};
    if (init) return f;
#ifdef _WIN32
    int regs[4] = {0, 0, 0, 0};
    for (unsigned i = 0; i < CPUIDPoolSize; ++i)
    {
        __cpuidex(regs, (int)CPUIDPool[i].Leaf, (int)CPUIDPool[i].Subleaf);
        f.EAX[i] = (uint32_t)regs[0];
        f.EBX[i] = (uint32_t)regs[1];
        f.ECX[i] = (uint32_t)regs[2];
        f.EDX[i] = (uint32_t)regs[3];
    }
    ReadKUserFields(f.KUSD);
    for (unsigned i = 0; i < MiscProbePoolSize; ++i)
    {
        uint64_t raw = 0;
        switch (MiscProbePool[i].Kind)
        {
            case MiscProbeKind::XGetBV: raw = ReadXCR0();       break;
            case MiscProbeKind::SMSW:   raw = ReadCR0ViaSMSW(); break;
        }
        const uint32_t folded = ((uint32_t)raw) ^ ((uint32_t)(raw >> 32));
        f.Misc[i] = folded & MiscProbePool[i].Mask;
    }
#endif
    init = true;
    return f;
}

uint64_t FoldFingerprint(const HwFingerprint& f, ArrayRef<unsigned> leafidxs, ArrayRef<unsigned> kuseridxs, ArrayRef<unsigned> miscidxs, uint8_t rothi, uint8_t rotlo)
{
    auto rol32 = [](uint32_t v, uint8_t r)
    {
        r &= 31; return (v << r) | (v >> (32 - r));
    };
    uint32_t hiraw = 0, loraw = 0;
    for (unsigned idx : leafidxs)
    {
        uint32_t ebx = f.EBX[idx];
        if (CPUIDPool[idx].MaskAPIC) ebx &= 0x00FFFFFFu;
        hiraw ^= f.EAX[idx] ^ f.ECX[idx];
        loraw ^= f.EDX[idx] ^ ebx;
    }
    FoldKUserIntoKey(f.KUSD, kuseridxs, hiraw, loraw);
    for (unsigned idx : miscidxs)
    {
        if (MiscProbePool[idx].ToHi) hiraw ^= f.Misc[idx];
        else loraw ^= f.Misc[idx];
    }
    const uint32_t hi = rol32(hiraw, rothi);
    const uint32_t lo = rol32(loraw, rotlo);
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

uint64_t ROL64(uint64_t v, uint8_t r)
{
    r &= 63;
    return (v << r) | (v >> (64 - r));
}

uint64_t ROR64(uint64_t v, uint8_t r)
{
    r &= 63;
    return (v >> r) | (v << (64 - r));
}

uint64_t ARXEncrypt(uint64_t plain, uint64_t k, uint8_t val1, uint8_t val2)
{
    uint64_t v = plain;
    v = v + k;
    v = ROL64(v, val1);
    v ^= k;
    v = v + k;
    v = ROR64(v, val2);
    return v;
}

uint64_t RandU64()
{
    std::uniform_int_distribution<uint64_t> d(0, ~(uint64_t)0);
    return d(GetPRNG());
}

uint8_t RandRot()
{
    std::uniform_int_distribution<unsigned> d(1, 63);
    return (uint8_t)d(GetPRNG());
}

std::vector<unsigned> PickLeaves(unsigned k, double hvbias)
{
    if (k == 0) k = 1;
    if (k > CPUIDPoolSize) k = CPUIDPoolSize;
    std::vector<unsigned> all;
    all.reserve(CPUIDPoolSize);
    for (unsigned i = 0; i < CPUIDPoolSize; ++i) all.push_back(i);
    std::shuffle(all.begin(), all.end(), GetPRNG());
    std::vector<unsigned> out(all.begin(), all.begin() + k);

    std::uniform_real_distribution<double> coin(0.0, 1.0);
    if (coin(GetPRNG()) < hvbias)
    {
        bool hashv = false;
        for (unsigned idx : out) if (CPUIDPool[idx].IsHV) { hashv = true; break; }
        if (!hashv)
        {
            std::vector<unsigned> hvpool;
            for (unsigned i = 0; i < CPUIDPoolSize; ++i)
                if (CPUIDPool[i].IsHV) hvpool.push_back(i);
            if (!hvpool.empty())
            {
                std::uniform_int_distribution<unsigned> pick(0, (unsigned)hvpool.size() - 1);
                out.back() = hvpool[pick(GetPRNG())];
            }
        }
    }
    return out;
}

std::vector<unsigned> PickMiscProbes(unsigned k)
{
    if (k == 0) return {};
    if (k > MiscProbePoolSize) k = MiscProbePoolSize;
    std::vector<unsigned> all;
    all.reserve(MiscProbePoolSize);
    for (unsigned i = 0; i < MiscProbePoolSize; ++i) all.push_back(i);
    std::shuffle(all.begin(), all.end(), GetPRNG());
    return std::vector<unsigned>(all.begin(), all.begin() + k);
}

std::string ComboKey(ArrayRef<unsigned> leafidxs, ArrayRef<unsigned> kuseridxs, ArrayRef<unsigned> miscidxs)
{
    auto join = [](std::vector<std::string>& v)
    {
        std::sort(v.begin(), v.end());
        std::string s;
        for (size_t i = 0; i < v.size(); ++i)
        {
            if (i) s += '+';
            s += v[i];
        }
        return s;
    };
    std::vector<std::string> ln, kn, mn;
    for (unsigned idx : leafidxs)  ln.emplace_back(CPUIDPool[idx].Name);
    for (unsigned idx : kuseridxs) kn.emplace_back(KUserPool[idx].Name);
    for (unsigned idx : miscidxs)  mn.emplace_back(MiscProbePool[idx].Name);
    std::string out = join(ln);
    if (!kn.empty()) { out += " | "; out += join(kn); }
    if (!mn.empty()) { out += " | "; out += join(mn); }
    return out;
}

Value* EmitCPUIDFoldKey(IRBuilder<>& b, ArrayRef<unsigned> leafidxs, ArrayRef<unsigned> kuseridxs, ArrayRef<unsigned> miscidxs, bool tscbracket, unsigned tscshift, uint8_t rothi, uint8_t rotlo, uint64_t seedlo)
{
    LLVMContext& c = b.getContext();
    Type* i64 = Type::getInt64Ty(c);

    std::string asmtmpl;
    asmtmpl.reserve(4096);
    asmtmpl += "mov r11, $3\n\t";
    asmtmpl += "mov qword ptr [rsp - 0x200], r11\n\t";

    if (tscbracket)
    {
        asmtmpl += "rdtsc\n\t";
        asmtmpl += "mov r15d, eax\n\t";
    }

    char buf[160];
    bool first = true;

    for (unsigned idx : leafidxs)
    {
        const LeafSpec& l = CPUIDPool[idx];
        if (l.Subleaf == 0)
        {
            asmtmpl += "xor ecx, ecx\n\t";
        }
        else
        {
            std::snprintf(buf, sizeof(buf), "mov ecx, 0x%08x\n\t", l.Subleaf);
            asmtmpl += buf;
        }
        std::snprintf(buf, sizeof(buf), "mov eax, 0x%08x\n\t", l.Leaf);
        asmtmpl += buf;
        asmtmpl += "cpuid\n\t";
        if (l.MaskAPIC) asmtmpl += "and ebx, 0x00FFFFFF\n\t";
        asmtmpl += "xor eax, ecx\n\t";
        asmtmpl += "xor edx, ebx\n\t";
        if (first)
        {
            asmtmpl += "mov r12d, eax\n\t";
            asmtmpl += "mov r13d, edx\n\t";
            first = false;
        }
        else
        {
            asmtmpl += "xor r12d, eax\n\t";
            asmtmpl += "xor r13d, edx\n\t";
        }
    }

    if (first)
    {
        asmtmpl += "xor r12d, r12d\n\t";
        asmtmpl += "xor r13d, r13d\n\t";
        first = false;
    }

    AppendKUserAsmSnippet(asmtmpl, kuseridxs);

    for (unsigned idx : miscidxs)
    {
        const MiscProbeSpec& p = MiscProbePool[idx];
        switch (p.Kind)
        {
            case MiscProbeKind::XGetBV:
                asmtmpl += "xor ecx, ecx\n\t";
                asmtmpl += "xgetbv\n\t";
                asmtmpl += "xor eax, edx\n\t";
                break;
            case MiscProbeKind::SMSW:
                asmtmpl += "smsw rax\n\t";
                break;
        }
        std::snprintf(buf, sizeof(buf), "and eax, 0x%08x\n\t", p.Mask);
        asmtmpl += buf;
        asmtmpl += p.ToHi ? "xor r12d, eax\n\t" : "xor r13d, eax\n\t";
    }

    if (tscbracket)
    {
        asmtmpl += "rdtsc\n\t";
        asmtmpl += "sub eax, r15d\n\t";
        std::snprintf(buf, sizeof(buf), "shr eax, %u\n\t", tscshift & 31);
        asmtmpl += buf;
        asmtmpl += "xor r12d, eax\n\t";
    }

    asmtmpl += "rol r12d, $1\n\t";
    asmtmpl += "rol r13d, $2\n\t";
    asmtmpl += "mov r11d, r12d\n\t";
    asmtmpl += "shl r11, 32\n\t";
    asmtmpl += "or r11, r13\n\t";
    asmtmpl += "xor r11, qword ptr [rsp - 0x200]\n\t";
    asmtmpl += "mov $0, r11";

    std::string constraints = "=r,n,n,i,~{rax},~{rbx},~{rcx},~{rdx},~{r11},~{r12},~{r13},~{r14},";
    if (tscbracket) constraints += "~{r15},";
    constraints += "~{memory},~{flags},~{dirflag},~{fpsr}";

    FunctionType* asmft = FunctionType::get(i64, {i64, i64, i64}, false);
    InlineAsm* ia = InlineAsm::get(asmft, asmtmpl, constraints, true, false, InlineAsm::AD_Intel);

    Value* a1 = ConstantInt::get(i64, (uint64_t)rothi);
    Value* a2 = ConstantInt::get(i64, (uint64_t)rotlo);
    Value* a3 = ConstantInt::get(i64, seedlo);
    return b.CreateCall(ia, {a1, a2, a3}, "LicKCpu");
}

Value* EmitARXDecrypt(IRBuilder<>& b, uint64_t enc, uint8_t val1, uint8_t val2, Value* k, Type* outty)
{
    LLVMContext& c = b.getContext();
    Type* i64 = Type::getInt64Ty(c);
    Module* m = b.GetInsertBlock()->getModule();
    Function* fshl = Intrinsic::getDeclaration(m, Intrinsic::fshl, {i64});
    Function* fshr = Intrinsic::getDeclaration(m, Intrinsic::fshr, {i64});

    Value* v = ConstantInt::get(i64, enc);
    v = b.CreateCall(fshl, {v, v, ConstantInt::get(i64, (uint64_t)val2)}, "LicR2I");
    v = b.CreateSub(v, k, "LicS2");
    v = b.CreateXor(v, k, "LicX1");
    v = b.CreateCall(fshr, {v, v, ConstantInt::get(i64, (uint64_t)val1)}, "LicR1I");
    v = b.CreateSub(v, k, "LicS1");

    if (outty->getIntegerBitWidth() < 64)
    {
        v = b.CreateTrunc(v, outty, "LicTr");
    }
    return v;
}