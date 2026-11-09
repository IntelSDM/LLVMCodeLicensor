#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "Disk.h"
#include "GPUAdapter.h"
#include "Imports.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace llvm;

const wchar_t* const DiskCandidates[DiskNumCandidates] =
{
    L"\\shell32.dll",
    L"\\imageres.dll",
    L"\\windows.ui.xaml.dll",
    L"\\ntoskrnl.exe",
    L"\\wmp.dll",
    L"\\combase.dll",
    L"\\mshtml.dll",
    L"\\twinui.pcshell.dll",
    L"\\mfcoreedge.dll",
    L"\\ntdll.dll",
};

#ifdef _WIN32

static HANDLE OpenDiskCandidateObf(unsigned idx, uint64_t* outsize)
{
    wchar_t path[MAX_PATH];
    DWORD n = GetSystemDirectoryW(path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH - 32) return INVALID_HANDLE_VALUE;
    const wchar_t* name = DiskCandidates[idx];
    DWORD i = n;
    for (DWORD k = 0; i < MAX_PATH - 1 && name[k]; ++i, ++k) path[i] = name[k];
    path[i] = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);
    if (h == INVALID_HANDLE_VALUE) return h;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || (uint64_t)sz.QuadPart < DiskMinFileSize)
    {
        CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }
    *outsize = (uint64_t)sz.QuadPart;
    return h;
}

static uint64_t LCGNextObf(uint64_t* s)
{
    *s = *s * 6364136223846793005ull + 1442695040888963407ull;
    return *s;
}

static double RandReadUsObf(HANDLE h, uint64_t filesize, char* buf, uint64_t* outdtticks)
{
    constexpr unsigned DiskRandInnerRuns = 3;

    uint64_t maxblocks = filesize / DiskSectorSize;
    if (maxblocks < 8) return 0.0;
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);

    uint64_t s = 0x2545F4914F6CDD1Dull;

    for (unsigned i = 0; i < DiskRandWarmup; ++i)
    {
        uint64_t off = (LCGNextObf(&s) % maxblocks) * DiskSectorSize;
        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)off;
        SetFilePointerEx(h, li, nullptr, FILE_BEGIN);
        DWORD did = 0;
        ReadFile(h, buf, DiskRandReadSize, &did, nullptr);
    }

    double bestus = 1e18;
    uint64_t bestdt = 0;
    for (unsigned r = 0; r < DiskRandInnerRuns; ++r)
    {
        LARGE_INTEGER t0, t1;
        QueryPerformanceCounter(&t0);
        for (unsigned i = 0; i < DiskRandReadCount; ++i)
        {
            uint64_t off = (LCGNextObf(&s) % maxblocks) * DiskSectorSize;
            LARGE_INTEGER li;
            li.QuadPart = (LONGLONG)off;
            SetFilePointerEx(h, li, nullptr, FILE_BEGIN);
            DWORD did = 0;
            ReadFile(h, buf, DiskRandReadSize, &did, nullptr);
        }
        QueryPerformanceCounter(&t1);
        const uint64_t dtticks = (uint64_t)(t1.QuadPart - t0.QuadPart);
        const double sec = (double)dtticks / (double)freq.QuadPart;
        const double us = sec * 1e6 / (double)DiskRandReadCount;
        if (us > 0.0 && us < bestus) { bestus = us; bestdt = dtticks; }
    }
    if (outdtticks) *outdtticks = bestdt;
    return (bestus < 1e18) ? bestus : 0.0;
}

static DiskBucketing ComputeDiskObfForCandidate(unsigned candidx)
{
    DiskBucketing bk;
    if (candidx >= DiskNumCandidates) return bk;

    char* buf = (char*)VirtualAlloc(nullptr, DiskSeqBufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return bk;

    uint64_t filesize = 0;
    HANDLE h = OpenDiskCandidateObf(candidx, &filesize);
    if (h == INVALID_HANDLE_VALUE)
    {
        VirtualFree(buf, 0, MEM_RELEASE);
        return bk;
    }

    uint64_t bestdt = 0;
    const double bestus = RandReadUsObf(h, filesize, buf, &bestdt);
    CloseHandle(h);
    VirtualFree(buf, 0, MEM_RELEASE);

    if (bestus >= 1e18) return bk;

    double dynedgesus[DiskNumEdges];
    {
        double prev = 0.0;
        for (unsigned i = 0; i < DiskNumEdges; ++i)
        {
            double e = bestus * (1.0 + DiskBucketStep * ((double)(int)i - (double)DiskCenterBucket + 0.5));
            const double eps = (std::max)(bestus * 0.01, 1e-6);
            if (e < prev + eps) e = prev + eps;
            dynedgesus[i] = e;
            prev = e;
        }
    }

    LARGE_INTEGER qpcfreq;
    QueryPerformanceFrequency(&qpcfreq);
    const double freqd = (double)qpcfreq.QuadPart;
    for (unsigned i = 0; i < DiskNumEdges; ++i)
    {
        const double dtedge = dynedgesus[i] * freqd * (double)DiskRandReadCount / 1e6;
        bk.RandEdgesTicks[i] = (uint64_t)dtedge;
        bk.RandEdges[i] = dynedgesus[i];
    }

    bk.CandidateIdx = (uint8_t)candidx;
    bk.RandMedianUs = bestus;
    bk.RandSpacing = DiskBucketStep;
    bk.BenchRuns = 3;
    bk.RandMedianDTTicks = bestdt;
    bk.Valid = true;
    return bk;
}

std::vector<DiskBucketing> ComputeDiskObfPool()
{
    std::vector<DiskBucketing> pool;
    pool.reserve(DiskNumCandidates);

    const HANDLE kthread = GetCurrentThread();
    const DWORD_PTR prevaffinity = SetThreadAffinityMask(kthread, 1);
    const DWORD prevprocclass = GetPriorityClass(GetCurrentProcess());
    const int prevthreadprio = GetThreadPriority(kthread);
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    SetThreadPriority(kthread, THREAD_PRIORITY_TIME_CRITICAL);

    for (unsigned i = 0; i < DiskNumCandidates; ++i)
    {
        DiskBucketing bk = ComputeDiskObfForCandidate(i);
        if (bk.Valid) pool.push_back(bk);
    }

    SetThreadPriority(kthread, prevthreadprio);
    SetPriorityClass(GetCurrentProcess(), prevprocclass);
    if (prevaffinity) SetThreadAffinityMask(kthread, prevaffinity);

    return pool;
}

#else
std::vector<DiskBucketing> ComputeDiskObfPool() { return {}; }
#endif

static uint64_t Djb2Hash(const char* s)
{
    uint64_t h = 5381;
    while (*s)
    {
        h = ((h << 5) + h) + (uint64_t)(uint8_t)(*s);
        ++s;
    }
    return h;
}

static GlobalVariable* MakeDiskPathGV(Module& m, const std::wstring& wpath)
{
    uint64_t pathhash = FNVInit;
    for (wchar_t w : wpath)
    {
        pathhash ^= (uint64_t)(uint16_t)w;
        pathhash *= FNVPrime;
    }
    char buf[48];
    std::snprintf(buf, sizeof(buf), "__lic_disk_path_%016llx", (unsigned long long)pathhash);
    const std::string gvn = buf;
    if (auto* ex = m.getGlobalVariable(gvn)) return ex;
    LLVMContext& c = m.getContext();
    SmallVector<Constant*, 320> vals;
    for (wchar_t w : wpath)
        vals.push_back(ConstantInt::get(Type::getInt16Ty(c), (uint16_t)w));
    vals.push_back(ConstantInt::get(Type::getInt16Ty(c), 0));
    ArrayType* at = ArrayType::get(Type::getInt16Ty(c), vals.size());
    auto* gv = new GlobalVariable(m, at, true, GlobalValue::PrivateLinkage, ConstantArray::get(at, vals), gvn);
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    gv->setAlignment(Align(2));
    return gv;
}

Value* EmitDiskInlineKey(IRBuilder<>& b, Module& m, const DiskBucketing& bk)
{
    LLVMContext& c = m.getContext();
    IntegerType* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    Type* ptrty = PointerType::get(c, 0);

    if (!bk.Valid)
    {
        return ConstantInt::get(i64, 1);
    }

    Instruction* useri = &*b.GetInsertPoint();
    BasicBlock* curbb = useri->getParent();
    Function* f = curbb->getParent();

    wchar_t sysdir[260] = {};
    unsigned sysdirlen = 0;
#ifdef _WIN32
    sysdirlen = GetSystemDirectoryW(sysdir, 260);
#endif
    std::wstring fullpath;
    if (sysdirlen && sysdirlen < 260)
    {
        fullpath.assign(sysdir, sysdirlen);
    }
    else
    {
        fullpath = L"C:\\Windows\\System32";
    }
    fullpath += DiskCandidates[bk.CandidateIdx];
    GlobalVariable* pathgv = MakeDiskPathGV(m, fullpath);

    FunctionType* cfwft = FunctionType::get(ptrty, {ptrty, i32, i32, ptrty, i32, i32, ptrty}, false);
    FunctionCallee cfw = DeclImport(m, "CreateFileW", cfwft);
    FunctionType* chft = FunctionType::get(i32, {ptrty}, false);
    FunctionCallee ch = DeclImport(m, "CloseHandle", chft);
    FunctionType* gfsft = FunctionType::get(i32, {ptrty, ptrty}, false);
    FunctionCallee gfs = DeclImport(m, "GetFileSizeEx", gfsft);
    FunctionType* sfpft = FunctionType::get(i32, {ptrty, i64, ptrty, i32}, false);
    FunctionCallee sfp = DeclImport(m, "SetFilePointerEx", sfpft);
    FunctionType* rfft = FunctionType::get(i32, {ptrty, ptrty, i32, ptrty, ptrty}, false);
    FunctionCallee rf = DeclImport(m, "ReadFile", rfft);
    FunctionType* vaft = FunctionType::get(ptrty, {ptrty, i64, i32, i32}, false);
    FunctionCallee va = DeclImport(m, "VirtualAlloc", vaft);
    FunctionType* vfft = FunctionType::get(i32, {ptrty, i64, i32}, false);
    FunctionCallee vf = DeclImport(m, "VirtualFree", vfft);
    FunctionType* qpft = FunctionType::get(i32, {ptrty}, false);
    FunctionCallee qpc = DeclImport(m, "QueryPerformanceCounter", qpft);

    IRBuilder<> eb(&f->getEntryBlock().front());
    AllocaInst* sz = eb.CreateAlloca(i64, nullptr, "P2DiskSz");
    AllocaInst* t0 = eb.CreateAlloca(i64, nullptr, "P2DiskT0");
    AllocaInst* t1 = eb.CreateAlloca(i64, nullptr, "P2DiskT1");
    AllocaInst* did = eb.CreateAlloca(i32, nullptr, "P2DiskDid");
    AllocaInst* lcg = eb.CreateAlloca(i64, nullptr, "P2DiskLcg");
    sz->setAlignment(Align(8));
    t0->setAlignment(Align(8));
    t1->setAlignment(Align(8));
    did->setAlignment(Align(4));
    lcg->setAlignment(Align(8));

    Value* nullptrv = ConstantPointerNull::get(cast<PointerType>(ptrty));
    constexpr uint32_t GenericRead = 0x80000000;
    constexpr uint32_t FileShareAll = 0x00000007;
    constexpr uint32_t OpenExisting = 3;
    constexpr uint32_t FlagNoBuffering = 0x20000000;
    constexpr uint32_t FileBegin = 0;
    constexpr uint32_t MemCommit = 0x1000;
    constexpr uint32_t MemReserve = 0x2000;
    constexpr uint32_t PageRW = 0x04;
    constexpr uint32_t MemRelease = 0x8000;

    BasicBlock* contbb = curbb->splitBasicBlock(useri, "P2DiskCont");
    curbb->getTerminator()->eraseFromParent();

    Instruction* curbbsplitpt = curbb->empty() ? nullptr : &curbb->back();

    BasicBlock* okalloc = BasicBlock::Create(c, "P2DiskOkAlloc", f, contbb);
    BasicBlock* failbb = BasicBlock::Create(c, "P2DiskFail", f, contbb);
    BasicBlock* okfile = BasicBlock::Create(c, "P2DiskOkFile", f, contbb);
    BasicBlock* failafterbuf = BasicBlock::Create(c, "P2DiskFab", f, contbb);
    BasicBlock* oksize = BasicBlock::Create(c, "P2DiskOkSize", f, contbb);
    BasicBlock* failafteropen = BasicBlock::Create(c, "P2DiskFao", f, contbb);
    BasicBlock* mergekbb = BasicBlock::Create(c, "P2DiskMergeK", f, contbb);

    Constant* failvirtualalloc = ConstantInt::get(i64, 0xDEAD0001ull);
    Constant* failcreatefile = ConstantInt::get(i64, 0xDEAD0002ull);
    Constant* failfiletoosmall = ConstantInt::get(i64, 0xDEAD0003ull);

    IRBuilder<> b2(curbb);
    Value* bufp = b2.CreateCall(va, {nullptrv, ConstantInt::get(i64, DiskSeqBufSize), ConstantInt::get(i32, MemCommit | MemReserve), ConstantInt::get(i32, PageRW)}, "P2DiskBuf");
    Value* bufbad = b2.CreateICmpEQ(bufp, nullptrv, "P2DiskBufBad");
    BasicBlock* bufbadbb = b2.GetInsertBlock();
    b2.CreateCondBr(bufbad, failbb, okalloc);

    IRBuilder<> oa(okalloc);
    Value* hcf = oa.CreateCall(cfw, {pathgv, ConstantInt::get(i32, GenericRead), ConstantInt::get(i32, FileShareAll), nullptrv, ConstantInt::get(i32, OpenExisting), ConstantInt::get(i32, FlagNoBuffering), nullptrv}, "P2DiskH");
    Value* hintval = oa.CreatePtrToInt(hcf, i64);
    Value* hbad = oa.CreateICmpEQ(hintval, ConstantInt::get(i64, (uint64_t)(int64_t)-1), "P2DiskHBad");
    oa.CreateCondBr(hbad, failafterbuf, okfile);

    IRBuilder<> fab(failafterbuf);
    fab.CreateCall(vf, {bufp, ConstantInt::get(i64, 0), ConstantInt::get(i32, MemRelease)});
    BasicBlock* fabtail = fab.GetInsertBlock();
    fab.CreateBr(failbb);

    IRBuilder<> of(okfile);
    of.CreateStore(ConstantInt::get(i64, 0), sz);
    of.CreateCall(gfs, {hcf, sz});
    LoadInst* szv = of.CreateLoad(i64, sz, "P2DiskSzV");
    szv->setAlignment(Align(8));
    Value* bigenough = of.CreateICmpUGE(szv, ConstantInt::get(i64, DiskMinFileSize), "P2DiskBig");
    of.CreateCondBr(bigenough, oksize, failafteropen);

    IRBuilder<> fao(failafteropen);
    fao.CreateCall(ch, {hcf});
    fao.CreateCall(vf, {bufp, ConstantInt::get(i64, 0), ConstantInt::get(i32, MemRelease)});
    BasicBlock* faotail = fao.GetInsertBlock();
    fao.CreateBr(failbb);

    IRBuilder<> os(oksize);
    Value* maxblocks = os.CreateUDiv(szv, ConstantInt::get(i64, DiskSectorSize), "P2DiskMb");

    auto insertraw = [&](Instruction* i, const char* name) -> Value*
    {
        i->setName(name);
        i->insertInto(os.GetInsertBlock(), os.GetInsertBlock()->end());
        return i;
    };

    os.CreateStore(ConstantInt::get(i64, 0x2545F4914F6CDD1Dull), lcg);
    Value* mbsafe = os.CreateSelect(os.CreateICmpEQ(maxblocks, ConstantInt::get(i64, 0)), ConstantInt::get(i64, 1), maxblocks, "P2DiskMbSafe");

    auto emitonerandread = [&]()
    {
        LoadInst* lcgv = os.CreateLoad(i64, lcg);
        lcgv->setAlignment(Align(8));
        Value* lcgn = os.CreateAdd(os.CreateMul(lcgv, ConstantInt::get(i64, 6364136223846793005ull)), ConstantInt::get(i64, 1442695040888963407ull));
        StoreInst* lcgst = os.CreateStore(lcgn, lcg);
        lcgst->setAlignment(Align(8));
        Value* mod = os.CreateURem(lcgn, mbsafe);
        Value* off = os.CreateMul(mod, ConstantInt::get(i64, DiskSectorSize));
        os.CreateCall(sfp, {hcf, off, nullptrv, ConstantInt::get(i32, FileBegin)});
        os.CreateStore(ConstantInt::get(i32, 0), did);
        os.CreateCall(rf, {hcf, bufp, ConstantInt::get(i32, DiskRandReadSize), did, nullptrv});
    };

    for (unsigned i = 0; i < DiskRandWarmup; ++i) emitonerandread();

    auto emitonetimedpass = [&]() -> Value*
    {
        os.CreateCall(qpc, {t0});
        for (unsigned ri = 0; ri < DiskRandReadCount; ++ri) emitonerandread();
        os.CreateCall(qpc, {t1});
        LoadInst* t0v = new LoadInst(i64, t0, "P2DiskPassT0", false, Align(8));
        insertraw(t0v, "P2DiskPassT0");
        LoadInst* t1v = new LoadInst(i64, t1, "P2DiskPassT1", false, Align(8));
        insertraw(t1v, "P2DiskPassT1");
        return insertraw(BinaryOperator::Create(Instruction::Sub, t1v, t0v), "P2DiskPassDt");
    };

    constexpr unsigned DiskRandInnerRuns = 3;
    Value* dts[DiskRandInnerRuns] = {nullptr, nullptr, nullptr};
    for (unsigned r = 0; r < DiskRandInnerRuns; ++r)
    {
        dts[r] = emitonetimedpass();
    }

    os.CreateCall(ch, {hcf});
    os.CreateCall(vf, {bufp, ConstantInt::get(i64, 0), ConstantInt::get(i32, MemRelease)});

    Value* lt01 = insertraw(ICmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_ULT, dts[0], dts[1]), "P2DiskLt01");
    Value* m01 = insertraw(SelectInst::Create(lt01, dts[0], dts[1]), "P2DiskM01");
    Value* lt012 = insertraw(ICmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_ULT, m01, dts[2]), "P2DiskLt012");
    Value* randdtraw = insertraw(SelectInst::Create(lt012, m01, dts[2]), "P2DiskRDtRaw");

    Value* mbsmall = insertraw(ICmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_ULT, maxblocks, ConstantInt::get(i64, 8)), "P2DiskMbSm");
    Value* randdt = insertraw(SelectInst::Create(mbsmall, ConstantInt::get(i64, (uint64_t)-1), randdtraw), "P2DiskRDt");

    Value* bucket = ConstantInt::get(i32, (uint32_t)DiskNumEdges);
    for (int i = (int)DiskNumEdges - 1; i >= 0; --i)
    {
        Constant* edgec = ConstantInt::get(i64, bk.RandEdgesTicks[i]);
        Value* cond = insertraw(ICmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_ULT, randdt, edgec), "P2DiskBkCmp");
        bucket = insertraw(SelectInst::Create(cond, ConstantInt::get(i32, (uint32_t)i), bucket), "P2DiskBkSel");
    }

    Value* h0 = ConstantInt::get(i64, FNVInit);
    Value* h1 = EmitFNVFoldU32(os, h0, ConstantInt::get(i32, (uint32_t)bk.CandidateIdx));
    Value* h2 = EmitFNVFoldU32(os, h1, bucket);
    Value* kraw = EmitSentinelSafe(os, h2);
    BasicBlock* oktail = os.GetInsertBlock();
    os.CreateBr(mergekbb);

    IRBuilder<> fb(failbb);
    PHINode* failphi = fb.CreatePHI(i64, 3, "P2DiskFailSrc");
    failphi->addIncoming(failvirtualalloc, bufbadbb);
    failphi->addIncoming(failcreatefile, fabtail);
    failphi->addIncoming(failfiletoosmall, faotail);
    BasicBlock* failtail = fb.GetInsertBlock();
    fb.CreateBr(mergekbb);

    IRBuilder<> mk(mergekbb);
    PHINode* kphi = mk.CreatePHI(i64, 2, "P2DiskK");
    kphi->addIncoming(kraw, oktail);
    kphi->addIncoming(failphi, failtail);
    mk.CreateBr(contbb);

 
    MDNode* disktag = MDNode::get(c, {});
    auto tagallinbb = [&](BasicBlock* bb)
    {
        for (Instruction& i : *bb) i.setMetadata("lic.p2.disk", disktag);
    };
    tagallinbb(okalloc);
    tagallinbb(failbb);
    tagallinbb(okfile);
    tagallinbb(failafterbuf);
    tagallinbb(oksize);
    tagallinbb(failafteropen);
    tagallinbb(mergekbb);
    {
        auto it = curbbsplitpt ? std::next(curbbsplitpt->getIterator()) : curbb->begin();
        for (; it != curbb->end(); ++it) it->setMetadata("lic.p2.disk", disktag);
    }

    b.SetInsertPoint(useri);
    return kphi;
}

bool HasDiskIDAnnotation(Function& f)
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
        if (cds->getAsCString() == "DiskID") return true;
    }
    return false;
}