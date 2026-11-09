#pragma once

#include "KUserSharedData.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"

#include <cstdint>
#include <string>
#include <vector>

struct LeafSpec
{
    uint32_t Leaf;
    uint32_t Subleaf;
    bool MaskAPIC;
    const char* Name;
    bool IsHV;
};
extern const LeafSpec CPUIDPool[];
extern const unsigned CPUIDPoolSize;

enum class MiscProbeKind : uint8_t { XGetBV, SMSW };

struct MiscProbeSpec
{
    MiscProbeKind Kind;
    uint32_t Mask;
    bool ToHi;
    const char* Name;
};
extern const MiscProbeSpec MiscProbePool[];
extern const unsigned MiscProbePoolSize;

#ifndef LICENSING_CPUID_POOL_MAX
#define LICENSING_CPUID_POOL_MAX 7
#endif
#ifndef LICENSING_MISC_POOL_MAX
#define LICENSING_MISC_POOL_MAX 2
#endif

struct HwFingerprint
{
    uint32_t EAX[LICENSING_CPUID_POOL_MAX];
    uint32_t EBX[LICENSING_CPUID_POOL_MAX];
    uint32_t ECX[LICENSING_CPUID_POOL_MAX];
    uint32_t EDX[LICENSING_CPUID_POOL_MAX];
    uint32_t KUSD[16];
    uint32_t Misc[LICENSING_MISC_POOL_MAX];
};

HwFingerprint GetObfFingerprint();

uint64_t FoldFingerprint(const HwFingerprint& f, llvm::ArrayRef<unsigned> leafidxs, llvm::ArrayRef<unsigned> kuseridxs, llvm::ArrayRef<unsigned> miscidxs, uint8_t rothi, uint8_t rotlo);

std::vector<unsigned> PickLeaves(unsigned k, double hvbias);
std::vector<unsigned> PickMiscProbes(unsigned k);
std::string ComboKey(llvm::ArrayRef<unsigned> leafidxs, llvm::ArrayRef<unsigned> kuseridxs, llvm::ArrayRef<unsigned> miscidxs);

uint64_t ROL64(uint64_t v, uint8_t r);
uint64_t ROR64(uint64_t v, uint8_t r);
uint64_t ARXEncrypt(uint64_t plain, uint64_t k, uint8_t val1, uint8_t val2);

llvm::Value* EmitARXDecrypt(llvm::IRBuilder<>& b, uint64_t enc, uint8_t val1, uint8_t val2, llvm::Value* k, llvm::Type* outty);

uint64_t RandU64();
uint8_t RandRot();

llvm::Value* EmitCPUIDFoldKey(llvm::IRBuilder<>& b, llvm::ArrayRef<unsigned> leafidxs, llvm::ArrayRef<unsigned> kuseridxs, llvm::ArrayRef<unsigned> miscidxs, bool tscbracket, unsigned tscshift, uint8_t rothi, uint8_t rotlo, uint64_t seedlo);