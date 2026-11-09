#pragma once

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

#include <cstdint>

static constexpr int DCDriverVersion = 0;
static constexpr int DCHorzRes = 8;
static constexpr int DCVertRes = 10;
static constexpr int DCBitsPixel = 12;

static constexpr int SMCxScreen = 0;
static constexpr int SMCyScreen = 1;
static constexpr int SMCMonitors = 80;
static constexpr int SMCxVirtualScreen = 78;
static constexpr int SMCyVirtualScreen = 79;

static constexpr unsigned DispDevSize = 840;
static constexpr unsigned DispDevCb = 0;
static constexpr unsigned DispDevDeviceName = 4;
static constexpr unsigned DispDevStateFlags = 324;
static constexpr unsigned DispDevDeviceID = 328;
static constexpr unsigned DispDevIDWChars = 128;

static constexpr unsigned DevModeSize = 220;
static constexpr unsigned DevModeDmSizeOff = 68;
static constexpr unsigned DevModeBitsPerPel = 168;
static constexpr unsigned DevModePelsWidth = 172;
static constexpr unsigned DevModePelsHeight = 176;
static constexpr unsigned DevModeDispFreq = 184;

static constexpr int32_t EnumCurrentSettings = -1;
static constexpr unsigned MaxDisplayProbe = 8;

uint64_t ComputeGDIFp();
uint64_t ComputeUser32Fp();
uint64_t ComputeDisplayFp();

llvm::Function* EnsureHelperGDI(llvm::Module& m);
llvm::Function* EnsureHelperUser32(llvm::Module& m);
llvm::Function* EnsureHelperDisplay(llvm::Module& m);

bool HasDisplayAdapterAnnotation(llvm::Function& f);