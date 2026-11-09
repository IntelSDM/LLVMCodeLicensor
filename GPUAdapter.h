#pragma once

#include "Disk.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

static constexpr uint64_t FNVInit = 0xcbf29ce484222325ULL;
static constexpr uint64_t FNVPrime = 0x100000001b3ULL;

uint64_t FNVFoldU32(uint64_t h, uint32_t v);
uint64_t SentinelSafe(uint64_t v);

extern const uint64_t VMemEdges[];
extern const unsigned NumVMemEdges;
uint32_t VMemBucket(uint64_t v);

extern const uint8_t IIDDXGIFactory1[16];
extern const uint8_t IIDD3D12Device[16];

static constexpr unsigned VtRelease = 2;
static constexpr unsigned VtEnumAdapters1 = 12;
static constexpr unsigned VtGetDesc1 = 10;
static constexpr unsigned MaxAdaptersProbe = 8;

static constexpr unsigned DescAlloc = 320;
static constexpr unsigned DescVendorId = 256;
static constexpr unsigned DescDeviceId = 260;
static constexpr unsigned DescSubSysId = 264;
static constexpr unsigned DescRevision = 268;
static constexpr unsigned DescVram = 272;
static constexpr unsigned DescFlags = 304;

static constexpr uint32_t D3DDriverTypeUnknown = 0;
static constexpr uint32_t D3D11SDKVersion = 7;

extern const uint32_t D3D12LevelsProbe[];
extern const unsigned NumD3D12Levels;
extern const uint32_t D3D11LevelsProbe[];
extern const unsigned NumD3D11Levels;

struct ObfGPUFp
{
    uint64_t DXGI = 0;
    uint64_t D3D11 = 0;
    uint64_t D3D12 = 0;
    uint64_t GDI = 0;
    uint64_t User32 = 0;
    uint64_t Display = 0;
    uint64_t Disk = 0;
    DiskBucketing DiskBuckets;
    std::vector<DiskBucketing> DiskPool;
    uint8_t HaveMask = 0;
};

uint64_t ComputeDXGIFp();
uint64_t ComputeD3DxFp(bool d3d12);

llvm::Function* EnsureHelperDXGI(llvm::Module& m);
llvm::Function* EnsureHelperD3Dx(llvm::Module& m, bool d3d12);

struct HelperScaffold
{
    llvm::Function* Fn;
    llvm::BasicBlock* EntryBB;
    llvm::BasicBlock* ComputeBB;
    llvm::BasicBlock* DoneBB;
    llvm::Value* CachedVal;
    llvm::GlobalVariable* Cache;
};

HelperScaffold BeginHelper(llvm::Module& m, const std::string& lane);
void FinalizeHelper(HelperScaffold& s, llvm::IRBuilder<>& compb, llvm::Value* raw64);

llvm::GlobalVariable* GetOrCreateGPUCache(llvm::Module& m, const std::string& lane);
llvm::GlobalVariable* MakeGUIDConst(llvm::Module& m, llvm::StringRef name, const uint8_t (&bytes)[16]);
void HoistAllocaToEntry(llvm::AllocaInst* a, llvm::BasicBlock* entrybb);
llvm::Value* EmitVtCall(llvm::IRBuilder<>& b, llvm::Value* thisptr, unsigned slot, llvm::FunctionType* fty, llvm::ArrayRef<llvm::Value*> args);
llvm::Value* EmitFNVFoldU32(llvm::IRBuilder<>& b, llvm::Value* h, llvm::Value* v32);
llvm::Value* EmitSentinelSafe(llvm::IRBuilder<>& b, llvm::Value* h64);
llvm::Value* EmitVMemBucket(llvm::IRBuilder<>& b, llvm::Value* v64);

struct AdapterLoopOut
{
    llvm::Value* HFinal;
    llvm::BasicBlock* EnumDoneBB;
};

AdapterLoopOut EmitAdapterLoop(llvm::Module& m, llvm::Function* f, llvm::BasicBlock* prebb, llvm::Value* factory, llvm::FunctionType* enumfty, llvm::FunctionType* getdescfty, llvm::FunctionType* releasefty, const std::function<llvm::Value*(llvm::IRBuilder<>&, llvm::Value*, llvm::Value*, llvm::Value*)>& foldadapter);

llvm::Value* EmitPerAdapterFold(llvm::IRBuilder<>& b, llvm::Value* descbuf, llvm::Value* hacc, llvm::Value* extrau32 = nullptr);

bool HasGPUAdapterAnnotation(llvm::Function& f);