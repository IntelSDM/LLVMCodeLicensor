#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

struct LicensingPass : llvm::PassInfoMixin<LicensingPass>
{
    llvm::PreservedAnalyses run(llvm::Module& m, llvm::ModuleAnalysisManager&);
};

bool RunLicensing(llvm::Module& m);
bool RunImports(llvm::Module& m);
bool RunConstEncryption(llvm::Module& m);
bool RunGadgets(llvm::Module& m);

extern llvm::cl::opt<bool> LicensingEnable;