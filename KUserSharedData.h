#pragma once

#include "llvm/ADT/ArrayRef.h"

#include <cstdint>
#include <string>
#include <vector>

struct KUserSpec
{
    uint32_t Offset;
    const char* Name;
    bool ToHi;
};

extern const KUserSpec KUserPool[];
extern const unsigned KUserPoolSize;

static constexpr uintptr_t KUserBase = 0x7FFE0000u;

void ReadKUserFields(uint32_t* out);
std::vector<unsigned> PickKUserFields(unsigned k);
void AppendKUserAsmSnippet(std::string& asmtmpl, llvm::ArrayRef<unsigned> kuseridxs);
void FoldKUserIntoKey(const uint32_t* kusdvalues, llvm::ArrayRef<unsigned> kuseridxs, uint32_t& hiraw, uint32_t& loraw);