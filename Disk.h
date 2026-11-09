#pragma once

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"

#include <cstdint>
#include <vector>

static constexpr unsigned DiskCenterBucket = 5;
static constexpr double DiskBucketStep = 0.60;
static constexpr double DiskBucketHalfWidth = 0.30;
static constexpr unsigned DiskNumEdges = 10;
static constexpr unsigned DiskNumCandidates = 10;

static constexpr unsigned DiskSectorSize = 4096;
static constexpr unsigned DiskSeqBufSize = 16u << 20;
static constexpr unsigned DiskRandReadSize = 4096;
static constexpr unsigned DiskRandReadCount = 128;
static constexpr unsigned DiskRandWarmup = 16;
static constexpr uint64_t DiskMinFileSize = 2ull << 20;

extern const wchar_t* const DiskCandidates[DiskNumCandidates];

struct DiskBucketing
{
    bool Valid = false;
    uint8_t CandidateIdx = 0;
    double RandEdges[DiskNumEdges] = {0};
    double RandMedianUs = 0.0;
    double RandSpacing = 0.0;
    unsigned BenchRuns = 0;
    uint64_t RandMedianDTTicks = 0;
    uint64_t RandEdgesTicks[DiskNumEdges] = {0};
};

std::vector<DiskBucketing> ComputeDiskObfPool();

llvm::Value* EmitDiskInlineKey(llvm::IRBuilder<>& b, llvm::Module& m, const DiskBucketing& bk);

bool HasDiskIDAnnotation(llvm::Function& f);