#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "DisplayAdapter.h"
#include "GPUAdapter.h"
#include "Imports.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Alignment.h"

#include <cstdint>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace llvm;

#ifdef _WIN32
uint64_t ComputeGDIFp()
{
    HDC hdc = GetDC(nullptr);
    if (!hdc) return 0;
    const int horz = GetDeviceCaps(hdc, DCHorzRes);
    const int vert = GetDeviceCaps(hdc, DCVertRes);
    const int bits = GetDeviceCaps(hdc, DCBitsPixel);
    const int drv = GetDeviceCaps(hdc, DCDriverVersion);
    ReleaseDC(nullptr, hdc);
    uint64_t h = FNVInit;
    h = FNVFoldU32(h, (uint32_t)horz);
    h = FNVFoldU32(h, (uint32_t)vert);
    h = FNVFoldU32(h, (uint32_t)bits);
    h = FNVFoldU32(h, (uint32_t)drv);
    return SentinelSafe(h);
}

uint64_t ComputeUser32Fp()
{
    const int cx = GetSystemMetrics(SMCxScreen);
    const int cy = GetSystemMetrics(SMCyScreen);
    const int n = GetSystemMetrics(SMCMonitors);
    const int vcx = GetSystemMetrics(SMCxVirtualScreen);
    const int vcy = GetSystemMetrics(SMCyVirtualScreen);
    uint64_t h = FNVInit;
    h = FNVFoldU32(h, (uint32_t)cx);
    h = FNVFoldU32(h, (uint32_t)cy);
    h = FNVFoldU32(h, (uint32_t)n);
    h = FNVFoldU32(h, (uint32_t)vcx);
    h = FNVFoldU32(h, (uint32_t)vcy);
    return SentinelSafe(h);
}

uint64_t ComputeDisplayFp()
{
    uint64_t h = FNVInit;

    DISPLAY_DEVICEW dd0{};
    dd0.cb = sizeof(dd0);
    DWORD nadapters = 0;
    bool havea0 = false;
    for (DWORD i = 0; ; ++i)
    {
        DISPLAY_DEVICEW dd{};
        dd.cb = sizeof(dd);
        if (!EnumDisplayDevicesW(nullptr, i, &dd, 0)) break;
        if (i == 0) { dd0 = dd; havea0 = true; }
        ++nadapters;
    }
    h = FNVFoldU32(h, (uint32_t)nadapters);
    if (!havea0) return 0;

    {
        uint64_t pa = FNVInit;
        for (size_t j = 0; j < 128 && dd0.DeviceID[j] != 0; ++j)
        {
            uint32_t w = (uint32_t)(uint16_t)dd0.DeviceID[j];
            pa = FNVFoldU32(pa, w);
        }
        h ^= pa;
    }
    h = FNVFoldU32(h, (uint32_t)dd0.StateFlags);

    DEVMODEW dm{};
    dm.dmSize = sizeof(dm);
    if (EnumDisplaySettingsExW(dd0.DeviceName, ENUM_CURRENT_SETTINGS, &dm, 0))
    {
        h = FNVFoldU32(h, (uint32_t)dm.dmPelsWidth);
        h = FNVFoldU32(h, (uint32_t)dm.dmPelsHeight);
        h = FNVFoldU32(h, (uint32_t)dm.dmBitsPerPel);
        h = FNVFoldU32(h, (uint32_t)dm.dmDisplayFrequency);
    }
    return SentinelSafe(h);
}
#else
uint64_t ComputeGDIFp()     { return 0; }
uint64_t ComputeUser32Fp()  { return 0; }
uint64_t ComputeDisplayFp() { return 0; }
#endif

Function* EnsureHelperGDI(Module& m)
{
    const std::string lane = "gdi";
    const std::string fnname = "__lic_gpu_fp_" + lane;
    if (Function* ex = m.getFunction(fnname)) return ex;

    LLVMContext& c = m.getContext();
    IntegerType* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    Type* ptrty = PointerType::get(c, 0);

    HelperScaffold s = BeginHelper(m, lane);

    FunctionType* gdcft = FunctionType::get(ptrty, {ptrty}, false);
    FunctionType* gdcapsft = FunctionType::get(i32, {ptrty, i32}, false);
    FunctionType* reldcft = FunctionType::get(i32, {ptrty, ptrty}, false);

    FunctionCallee gdc = DeclImport(m, "GetDC", gdcft);
    FunctionCallee gdcaps = DeclImport(m, "GetDeviceCaps", gdcapsft);
    FunctionCallee reldc = DeclImport(m, "ReleaseDC", reldcft);

    IRBuilder<> b(s.ComputeBB);
    Value* nullwnd = ConstantPointerNull::get(cast<PointerType>(ptrty));
    Value* hdc = b.CreateCall(gdc, {nullwnd}, "Hdc");
    Value* hdcok = b.CreateICmpNE(hdc, ConstantPointerNull::get(cast<PointerType>(ptrty)), "HdcOk");
    BasicBlock* okbb = BasicBlock::Create(c, "HdcOk", s.Fn);
    BasicBlock* badbb = BasicBlock::Create(c, "HdcBad", s.Fn);
    b.CreateCondBr(hdcok, okbb, badbb);

    IRBuilder<> ok(okbb);
    Value* horz = ok.CreateCall(gdcaps, {hdc, ConstantInt::get(i32, DCHorzRes)}, "Horz");
    Value* vert = ok.CreateCall(gdcaps, {hdc, ConstantInt::get(i32, DCVertRes)}, "Vert");
    Value* bits = ok.CreateCall(gdcaps, {hdc, ConstantInt::get(i32, DCBitsPixel)}, "Bits");
    Value* drv = ok.CreateCall(gdcaps, {hdc, ConstantInt::get(i32, DCDriverVersion)}, "Drv");
    ok.CreateCall(reldc, {nullwnd, hdc});
    Value* h = ConstantInt::get(i64, FNVInit);
    h = EmitFNVFoldU32(ok, h, horz);
    h = EmitFNVFoldU32(ok, h, vert);
    h = EmitFNVFoldU32(ok, h, bits);
    h = EmitFNVFoldU32(ok, h, drv);

    BasicBlock* mergebb = BasicBlock::Create(c, "Merge", s.Fn);
    ok.CreateBr(mergebb);

    IRBuilder<> bd(badbb);
    Value* failval = ConstantInt::get(i64, 1);
    bd.CreateBr(mergebb);

    IRBuilder<> mg(mergebb);
    PHINode* merged = mg.CreatePHI(i64, 2, "M");
    merged->addIncoming(h, okbb);
    merged->addIncoming(failval, badbb);
    FinalizeHelper(s, mg, merged);
    return s.Fn;
}

Function* EnsureHelperUser32(Module& m)
{
    const std::string lane = "user32";
    const std::string fnname = "__lic_gpu_fp_" + lane;
    if (Function* ex = m.getFunction(fnname)) return ex;

    LLVMContext& c = m.getContext();
    IntegerType* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);

    HelperScaffold s = BeginHelper(m, lane);

    FunctionType* gsmft = FunctionType::get(i32, {i32}, false);
    FunctionCallee gsm = DeclImport(m, "GetSystemMetrics", gsmft);

    IRBuilder<> b(s.ComputeBB);
    Value* cx = b.CreateCall(gsm, {ConstantInt::get(i32, SMCxScreen)}, "Cx");
    Value* cy = b.CreateCall(gsm, {ConstantInt::get(i32, SMCyScreen)}, "Cy");
    Value* nm = b.CreateCall(gsm, {ConstantInt::get(i32, SMCMonitors)}, "Nm");
    Value* vcx = b.CreateCall(gsm, {ConstantInt::get(i32, SMCxVirtualScreen)}, "Vcx");
    Value* vcy = b.CreateCall(gsm, {ConstantInt::get(i32, SMCyVirtualScreen)}, "Vcy");
    Value* h = ConstantInt::get(i64, FNVInit);
    h = EmitFNVFoldU32(b, h, cx);
    h = EmitFNVFoldU32(b, h, cy);
    h = EmitFNVFoldU32(b, h, nm);
    h = EmitFNVFoldU32(b, h, vcx);
    h = EmitFNVFoldU32(b, h, vcy);
    FinalizeHelper(s, b, h);
    return s.Fn;
}

Function* EnsureHelperDisplay(Module& m)
{
    const std::string lane = "display";
    const std::string fnname = "__lic_gpu_fp_" + lane;
    if (Function* ex = m.getFunction(fnname)) return ex;

    LLVMContext& c = m.getContext();
    Type* i8 = Type::getInt8Ty(c);
    Type* i16 = Type::getInt16Ty(c);
    IntegerType* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    Type* ptrty = PointerType::get(c, 0);

    HelperScaffold s = BeginHelper(m, lane);

    FunctionType* eddft = FunctionType::get(i32, {ptrty, i32, ptrty, i32}, false);
    FunctionCallee edd = DeclImport(m, "EnumDisplayDevicesW", eddft);

    FunctionType* essft = FunctionType::get(i32, {ptrty, i32, ptrty, i32}, false);
    FunctionCallee ess = DeclImport(m, "EnumDisplaySettingsExW", essft);

    IRBuilder<> b(s.ComputeBB);
    ArrayType* ddarrt = ArrayType::get(i8, DispDevSize);
    AllocaInst* dd0 = b.CreateAlloca(ddarrt, nullptr, "Dd0");
    dd0->setAlignment(Align(8));
    HoistAllocaToEntry(dd0, s.EntryBB);
    ArrayType* ddtmpt = ArrayType::get(i8, DispDevSize);
    AllocaInst* ddtmp = b.CreateAlloca(ddtmpt, nullptr, "DdTmp");
    ddtmp->setAlignment(Align(8));
    HoistAllocaToEntry(ddtmp, s.EntryBB);
    ArrayType* dmarrt = ArrayType::get(i8, DevModeSize);
    AllocaInst* dm = b.CreateAlloca(dmarrt, nullptr, "Dm");
    dm->setAlignment(Align(8));
    HoistAllocaToEntry(dm, s.EntryBB);

    b.CreateMemSet(dd0,   ConstantInt::get(i8, 0), ConstantInt::get(i64, DispDevSize), Align(8));
    b.CreateMemSet(ddtmp, ConstantInt::get(i8, 0), ConstantInt::get(i64, DispDevSize), Align(8));
    b.CreateMemSet(dm,    ConstantInt::get(i8, 0), ConstantInt::get(i64, DevModeSize), Align(8));

    auto storeu32at = [&](Value* base, unsigned off, Value* v)
    {
        Value* p = b.CreateGEP(i8, base, ConstantInt::get(i64, off));
        StoreInst* st = b.CreateStore(v, p);
        st->setAlignment(Align(1));
    };
    auto storeu16at = [&](Value* base, unsigned off, Value* v)
    {
        Value* p = b.CreateGEP(i8, base, ConstantInt::get(i64, off));
        StoreInst* st = b.CreateStore(v, p);
        st->setAlignment(Align(1));
    };
    storeu32at(dd0, DispDevCb, ConstantInt::get(i32, DispDevSize));
    storeu16at(dm,  DevModeDmSizeOff, ConstantInt::get(i16, DevModeSize));

    Value* nullptrv = ConstantPointerNull::get(cast<PointerType>(ptrty));

    BasicBlock* loophdr = BasicBlock::Create(c, "DspHdr", s.Fn);
    BasicBlock* loopbody = BasicBlock::Create(c, "DspBody", s.Fn);
    BasicBlock* copybb = BasicBlock::Create(c, "DspCpy0", s.Fn);
    BasicBlock* loopcont = BasicBlock::Create(c, "DspCont", s.Fn);
    BasicBlock* loopend = BasicBlock::Create(c, "DspEnd", s.Fn);
    b.CreateBr(loophdr);

    IRBuilder<> h(loophdr);
    PHINode* iphi = h.CreatePHI(i32, 2, "I");
    iphi->addIncoming(ConstantInt::get(i32, 0), s.ComputeBB);
    PHINode* nphi = h.CreatePHI(i32, 2, "N");
    nphi->addIncoming(ConstantInt::get(i32, 0), s.ComputeBB);
    Value* cbslot = h.CreateGEP(i8, ddtmp, ConstantInt::get(i64, DispDevCb));
    StoreInst* stcb = h.CreateStore(ConstantInt::get(i32, DispDevSize), cbslot);
    stcb->setAlignment(Align(1));
    Value* r = h.CreateCall(edd, {nullptrv, iphi, ddtmp, ConstantInt::get(i32, 0)}, "DspR");
    Value* ok = h.CreateICmpNE(r, ConstantInt::get(i32, 0), "DspOk");
    h.CreateCondBr(ok, loopbody, loopend);

    IRBuilder<> bo(loopbody);
    Value* nnext = bo.CreateAdd(nphi, ConstantInt::get(i32, 1), "NN");
    Value* is0 = bo.CreateICmpEQ(iphi, ConstantInt::get(i32, 0), "Is0");
    bo.CreateCondBr(is0, copybb, loopcont);

    IRBuilder<> cp(copybb);
    cp.CreateMemCpy(dd0, Align(8), ddtmp, Align(8), ConstantInt::get(i64, DispDevSize));
    cp.CreateBr(loopcont);

    IRBuilder<> lc(loopcont);
    Value* inext = lc.CreateAdd(iphi, ConstantInt::get(i32, 1), "IN");
    Value* more = lc.CreateICmpULT(inext, ConstantInt::get(i32, MaxDisplayProbe), "More");
    lc.CreateCondBr(more, loophdr, loopend);
    iphi->addIncoming(inext, loopcont);
    nphi->addIncoming(nnext, loopcont);

    IRBuilder<> e(loopend);
    PHINode* nfinal = e.CreatePHI(i32, 2, "NFin");
    nfinal->addIncoming(nphi, loophdr);
    nfinal->addIncoming(nnext, loopcont);
    Value* havea0 = e.CreateICmpNE(nfinal, ConstantInt::get(i32, 0), "HaveA0");

    BasicBlock* goodbb = BasicBlock::Create(c, "DspGood", s.Fn);
    BasicBlock* badbb = BasicBlock::Create(c, "DspBad", s.Fn);
    e.CreateCondBr(havea0, goodbb, badbb);

    IRBuilder<> g(goodbb);
    Value* fnvh = ConstantInt::get(i64, FNVInit);
    fnvh = EmitFNVFoldU32(g, fnvh, nfinal);

    BasicBlock* idhdr = BasicBlock::Create(c, "DspIdHdr", s.Fn);
    BasicBlock* idbody = BasicBlock::Create(c, "DspIdBd", s.Fn);
    BasicBlock* idexit = BasicBlock::Create(c, "DspIdEx", s.Fn);
    Value* painit = ConstantInt::get(i64, FNVInit);
    g.CreateBr(idhdr);

    IRBuilder<> ih(idhdr);
    PHINode* jphi = ih.CreatePHI(i32, 2, "J");
    jphi->addIncoming(ConstantInt::get(i32, 0), goodbb);
    PHINode* paphi = ih.CreatePHI(i64, 2, "Pa");
    paphi->addIncoming(painit, goodbb);
    Value* jlt = ih.CreateICmpULT(jphi, ConstantInt::get(i32, DispDevIDWChars), "JLt");
    Value* wideptr = ih.CreateGEP(i8, dd0, ih.CreateAdd(ConstantInt::get(i32, DispDevDeviceID), ih.CreateMul(jphi, ConstantInt::get(i32, 2))), "IdP");
    LoadInst* w = ih.CreateLoad(i16, wideptr, "W");
    w->setAlignment(Align(1));
    Value* notnul = ih.CreateICmpNE(w, ConstantInt::get(i16, 0), "Nn");
    Value* cont = ih.CreateAnd(jlt, notnul, "Cont");
    ih.CreateCondBr(cont, idbody, idexit);

    IRBuilder<> ib(idbody);
    Value* w32 = ib.CreateZExt(w, i32, "W32");
    Value* panext = EmitFNVFoldU32(ib, paphi, w32);
    Value* jnext = ib.CreateAdd(jphi, ConstantInt::get(i32, 1), "JN");
    ib.CreateBr(idhdr);
    jphi->addIncoming(jnext, idbody);
    paphi->addIncoming(panext, idbody);

    IRBuilder<> ix(idexit);
    Value* hafterid = ix.CreateXor(fnvh, paphi, "HId");

    Value* sfptr = ix.CreateGEP(i8, dd0, ConstantInt::get(i32, DispDevStateFlags), "SfP");
    LoadInst* sf = ix.CreateLoad(i32, sfptr, "Sf");
    sf->setAlignment(Align(1));
    Value* haftersf = EmitFNVFoldU32(ix, hafterid, sf);

    Value* devnameptr = ix.CreateGEP(i8, dd0, ConstantInt::get(i32, DispDevDeviceName), "DnP");
    Value* dmsizeptr = ix.CreateGEP(i8, dm, ConstantInt::get(i32, DevModeDmSizeOff), "DmSzP");
    StoreInst* stdmsz = ix.CreateStore(ConstantInt::get(i16, DevModeSize), dmsizeptr);
    stdmsz->setAlignment(Align(1));
    Value* essr = ix.CreateCall(ess, {devnameptr, ConstantInt::get(i32, EnumCurrentSettings), dm, ConstantInt::get(i32, 0)}, "EssR");
    Value* essok = ix.CreateICmpNE(essr, ConstantInt::get(i32, 0), "EssOk");

    BasicBlock* modebb = BasicBlock::Create(c, "DspMode", s.Fn);
    BasicBlock* mergebb = BasicBlock::Create(c, "DspMerge", s.Fn);
    ix.CreateCondBr(essok, modebb, mergebb);

    IRBuilder<> md(modebb);
    auto readu32 = [&](Value* base, unsigned off, const char* n) -> Value*
    {
        Value* p = md.CreateGEP(i8, base, ConstantInt::get(i32, off), n);
        LoadInst* ld = md.CreateLoad(i32, p, n);
        ld->setAlignment(Align(1));
        return ld;
    };
    Value* pw = readu32(dm, DevModePelsWidth,  "Pw");
    Value* ph = readu32(dm, DevModePelsHeight, "Ph");
    Value* bp = readu32(dm, DevModeBitsPerPel, "Bp");
    Value* fq = readu32(dm, DevModeDispFreq,   "Fq");
    Value* hmode = EmitFNVFoldU32(md, haftersf, pw);
    hmode = EmitFNVFoldU32(md, hmode, ph);
    hmode = EmitFNVFoldU32(md, hmode, bp);
    hmode = EmitFNVFoldU32(md, hmode, fq);
    BasicBlock* modeendbb = md.GetInsertBlock();
    md.CreateBr(mergebb);

    IRBuilder<> bd(badbb);
    Value* failval = ConstantInt::get(i64, 1);
    bd.CreateBr(mergebb);

    IRBuilder<> mg(mergebb);
    PHINode* finalh = mg.CreatePHI(i64, 3, "Final");
    finalh->addIncoming(hmode, modeendbb);
    finalh->addIncoming(haftersf, idexit);
    finalh->addIncoming(failval, badbb);
    FinalizeHelper(s, mg, finalh);
    return s.Fn;
}

bool HasDisplayAdapterAnnotation(Function& f)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga || !ga->hasInitializer()) return false;
    auto* ca = dyn_cast<ConstantArray>(ga->getInitializer());
    if (!ca) return false;
    for (unsigned i = 0, e = ca->getNumOperands(); i < e; ++i)
    {
        auto* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs || cs->getNumOperands() < 2) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;
        auto* gv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!gv || !gv->hasInitializer()) continue;
        auto* cds = dyn_cast<ConstantDataArray>(gv->getInitializer());
        if (!cds || !cds->isCString()) continue;
        if (cds->getAsCString() == "DisplayAdapter") return true;
    }
    return false;
}