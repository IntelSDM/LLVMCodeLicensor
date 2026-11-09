#pragma once

#include "DLLHelper/DLLExportGrabber.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

extern const char* const SeedHostPool[];
extern const unsigned SeedHostPoolSize;

struct HostState
{
    std::string DLLLower;
    bool Sourced = false;
    std::wstring CanonicalPath;
    DLLExportGrabber::ExportTable Exports;
};

bool SourceHost(const std::string& hostlower, HostState& out);

bool ResolveImport(const std::string& firsthost, const std::string& firstname, std::map<std::string, HostState>& hosts, std::string& outhost, uint32_t& outrva, std::string& outreason);

bool IsRealCodeExport(const std::wstring& dllpath, uint32_t rva);

std::string UnmangleCName(llvm::StringRef n);

bool IsEligibleDLLImport(const llvm::Function& f);

static constexpr uint8_t ImpMaskDXGI = 1 << 0;
static constexpr uint8_t ImpMaskD3D11 = 1 << 1;
static constexpr uint8_t ImpMaskD3D12 = 1 << 2;
static constexpr uint8_t ImpMaskGDI = 1 << 3;
static constexpr uint8_t ImpMaskUser32 = 1 << 4;
static constexpr uint8_t ImpMaskDisplay = 1 << 5;
static constexpr uint8_t ImpMaskDisk = 1 << 6;

static constexpr uint8_t OfMaskDXGI = 1 << 0;
static constexpr uint8_t OfMaskD3D11 = 1 << 1;
static constexpr uint8_t OfMaskD3D12 = 1 << 2;
static constexpr uint8_t OfMaskGDI = 1 << 3;
static constexpr uint8_t OfMaskUser32 = 1 << 4;
static constexpr uint8_t OfMaskDisplay = 1 << 5;
static constexpr uint8_t OfMaskDisk = 1 << 6;

uint8_t DiscoverGPUImportMask(llvm::Module& m);
uint8_t GPUAvailableMask(uint8_t impmask, uint8_t obfmask);
std::vector<std::string> DiscoverImportedDLLs(llvm::Module& m);

llvm::FunctionCallee DeclGetModuleHandleA(llvm::Module& m);
llvm::GlobalVariable* GetOrCreateHostNameGV(llvm::Module& m, const std::string& host);
llvm::FunctionCallee DeclImport(llvm::Module& m, llvm::StringRef name, llvm::FunctionType* ft);
void ResetHostNameGVCache();