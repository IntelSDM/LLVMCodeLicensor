#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "GPUAdapter.h"
#include "Imports.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Alignment.h"

#include <cstdint>
#include <cstring>
#include <functional>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace llvm;

uint64_t FNVFoldU32(uint64_t h, uint32_t v)
{
    for (int i = 0; i < 4; ++i)
    {
        h ^= (uint64_t)((v >> (i * 8)) & 0xFF);
        h *= FNVPrime;
    }
    return h;
}

uint64_t SentinelSafe(uint64_t v)
{
    if (v == 0 || v == ~(uint64_t)0) return 1;
    return v;
}

const uint64_t VMemEdges[] =
{
    128ull << 20, 256ull << 20, 512ull << 20, 1024ull << 20,
    2048ull << 20, 4096ull << 20, 6144ull << 20, 8192ull << 20,
    12288ull << 20, 16384ull << 20, 24576ull << 20, 32768ull << 20,
    49152ull << 20,
};
const unsigned NumVMemEdges = sizeof(VMemEdges) / sizeof(VMemEdges[0]);

uint32_t VMemBucket(uint64_t v)
{
    for (unsigned i = 0; i < NumVMemEdges; ++i)
        if (v < VMemEdges[i]) return i;
    return NumVMemEdges;
}

const uint8_t IIDDXGIFactory1[16] =
{
    0x78, 0xAE, 0x0A, 0x77, 0x6F, 0xF2, 0xBA, 0x4D,
    0xA8, 0x29, 0x25, 0x3C, 0x83, 0xD1, 0xB3, 0x87
};

const uint8_t IIDD3D12Device[16] =
{
    0xF1, 0x19, 0x98, 0x18, 0xB6, 0x1D, 0x57, 0x4B,
    0xBE, 0x54, 0x18, 0x21, 0x33, 0x9B, 0x85, 0xF7
};

const uint32_t D3D12LevelsProbe[] = { 0xc200, 0xc100, 0xc000, 0xb100, 0xb000 };
const unsigned NumD3D12Levels = sizeof(D3D12LevelsProbe) / sizeof(D3D12LevelsProbe[0]);

const uint32_t D3D11LevelsProbe[] = { 0xc100, 0xc000, 0xb100, 0xb000 };
const unsigned NumD3D11Levels = sizeof(D3D11LevelsProbe) / sizeof(D3D11LevelsProbe[0]);

#ifdef _WIN32
typedef struct { uint8_t b[16]; } ObfGUID;

uint64_t ComputeDXGIFp()
{
    HMODULE hdxgi = LoadLibraryA("dxgi.dll");
    if (!hdxgi) return 0;
    typedef long (__stdcall *PFNCDF1)(const void*, void**);
    auto pcdf1 = (PFNCDF1)GetProcAddress(hdxgi, "CreateDXGIFactory1");
    if (!pcdf1) return 0;

    ObfGUID gid;
    std::memcpy(gid.b, IIDDXGIFactory1, 16);
    void* factory = nullptr;
    if (pcdf1(&gid, &factory) != 0 || !factory) return 0;

    void** fvtbl = *(void***)factory;
    typedef long (__stdcall *PFNEnum1)(void*, UINT, void**);
    typedef unsigned long (__stdcall *PFNRelease)(void*);
    auto penum = (PFNEnum1)fvtbl[VtEnumAdapters1];
    auto prelf = (PFNRelease)fvtbl[VtRelease];

    uint64_t h = FNVInit;
    for (UINT i = 0; i < MaxAdaptersProbe; ++i)
    {
        void* adap = nullptr;
        if (penum(factory, i, &adap) != 0 || !adap) break;
        uint8_t desc[DescAlloc] = {};
        void** avtbl = *(void***)adap;
        typedef long (__stdcall *PFNGD1)(void*, void*);
        auto pgd = (PFNGD1)avtbl[VtGetDesc1];
        if (pgd(adap, desc) == 0)
        {
            uint32_t ven, dev, sub, rev, flags;
            uint64_t vram;
            std::memcpy(&ven,   desc + DescVendorId, 4);
            std::memcpy(&dev,   desc + DescDeviceId, 4);
            std::memcpy(&sub,   desc + DescSubSysId, 4);
            std::memcpy(&rev,   desc + DescRevision, 4);
            std::memcpy(&vram,  desc + DescVram,     8);
            std::memcpy(&flags, desc + DescFlags,    4);
            uint64_t pa = FNVInit;
            pa = FNVFoldU32(pa, (ven << 16) | (dev & 0xFFFF));
            pa = FNVFoldU32(pa, sub);
            pa = FNVFoldU32(pa, rev);
            pa = FNVFoldU32(pa, VMemBucket(vram));
            pa = FNVFoldU32(pa, flags);
            h ^= pa;
        }
        auto prela = (PFNRelease)avtbl[VtRelease];
        prela(adap);
    }
    prelf(factory);
    return SentinelSafe(h);
}

uint64_t ComputeD3DxFp(bool d3d12)
{
    HMODULE hdxgi = LoadLibraryA("dxgi.dll");
    if (!hdxgi) return 0;
    HMODULE hdx = LoadLibraryA(d3d12 ? "d3d12.dll" : "d3d11.dll");
    if (!hdx) return 0;

    typedef long (__stdcall *PFNCDF1)(const void*, void**);
    auto pcdf1 = (PFNCDF1)GetProcAddress(hdxgi, "CreateDXGIFactory1");
    if (!pcdf1) return 0;

    typedef long (__stdcall *PFND12)(void*, UINT, const void*, void**);
    typedef long (__stdcall *PFND11)(void*, UINT, HMODULE, UINT, const UINT*, UINT, UINT, void**, UINT*, void**);
    PFND12 pd12 = nullptr;
    PFND11 pd11 = nullptr;
    if (d3d12) pd12 = (PFND12)GetProcAddress(hdx, "D3D12CreateDevice");
    else       pd11 = (PFND11)GetProcAddress(hdx, "D3D11CreateDevice");
    if ((d3d12 && !pd12) || (!d3d12 && !pd11)) return 0;

    ObfGUID gidfac;
    std::memcpy(gidfac.b, IIDDXGIFactory1, 16);
    ObfGUID giddev;
    std::memcpy(giddev.b, IIDD3D12Device, 16);
    void* factory = nullptr;
    if (pcdf1(&gidfac, &factory) != 0 || !factory) return 0;

    void** fvtbl = *(void***)factory;
    typedef long (__stdcall *PFNEnum1)(void*, UINT, void**);
    typedef unsigned long (__stdcall *PFNRelease)(void*);
    auto penum = (PFNEnum1)fvtbl[VtEnumAdapters1];
    auto prelf = (PFNRelease)fvtbl[VtRelease];

    uint64_t h = FNVInit;
    for (UINT i = 0; i < MaxAdaptersProbe; ++i)
    {
        void* adap = nullptr;
        if (penum(factory, i, &adap) != 0 || !adap) break;
        uint8_t desc[DescAlloc] = {};
        void** avtbl = *(void***)adap;
        typedef long (__stdcall *PFNGD1)(void*, void*);
        auto pgd = (PFNGD1)avtbl[VtGetDesc1];
        if (pgd(adap, desc) == 0)
        {
            uint32_t ven, dev, sub, rev, flags;
            uint64_t vram;
            std::memcpy(&ven,   desc + DescVendorId, 4);
            std::memcpy(&dev,   desc + DescDeviceId, 4);
            std::memcpy(&sub,   desc + DescSubSysId, 4);
            std::memcpy(&rev,   desc + DescRevision, 4);
            std::memcpy(&vram,  desc + DescVram,     8);
            std::memcpy(&flags, desc + DescFlags,    4);

            uint32_t maxfl = 0;
            if (d3d12)
            {
                for (unsigned k = 0; k < NumD3D12Levels; ++k)
                {
                    long hr = pd12(adap, D3D12LevelsProbe[k], &giddev, nullptr);
                    if (hr >= 0) { maxfl = D3D12LevelsProbe[k]; break; }
                }
            }
            else
            {
                UINT actual = 0;
                long hr = pd11(adap, D3DDriverTypeUnknown, nullptr, 0, D3D11LevelsProbe, NumD3D11Levels, D3D11SDKVersion, nullptr, &actual, nullptr);
                if (hr >= 0) maxfl = actual;
            }

            uint64_t pa = FNVInit;
            pa = FNVFoldU32(pa, (ven << 16) | (dev & 0xFFFF));
            pa = FNVFoldU32(pa, sub);
            pa = FNVFoldU32(pa, rev);
            pa = FNVFoldU32(pa, VMemBucket(vram));
            pa = FNVFoldU32(pa, flags);
            pa = FNVFoldU32(pa, maxfl);
            h ^= pa;
        }
        auto prela = (PFNRelease)avtbl[VtRelease];
        prela(adap);
    }
    prelf(factory);
    return SentinelSafe(h);
}
#else
uint64_t ComputeDXGIFp() { return 0; }
uint64_t ComputeD3DxFp(bool) { return 0; }
#endif

GlobalVariable* GetOrCreateGPUCache(Module& m, const std::string& lane)
{
    const std::string name = "__lic_gpu_cache_" + lane;
    if (auto* ex = m.getGlobalVariable(name)) return ex;
    LLVMContext& c = m.getContext();
    Type* i64 = Type::getInt64Ty(c);
    auto* gv = new GlobalVariable(m, i64, false, GlobalValue::InternalLinkage, ConstantInt::get(i64, 0), name);
    gv->setAlignment(Align(8));
    return gv;
}

HelperScaffold BeginHelper(Module& m, const std::string& lane)
{
    LLVMContext& c = m.getContext();
    Type* i64 = Type::getInt64Ty(c);

    const std::string fnname = "__lic_gpu_fp_" + lane;
    FunctionType* ft = FunctionType::get(i64, {}, false);
    Function* f = Function::Create(ft, GlobalValue::InternalLinkage, fnname, m);
    f->setDoesNotThrow();
    f->addFnAttr(Attribute::NoInline);
    f->addFnAttr(Attribute::OptimizeNone);
    f->addFnAttr(Attribute::NoUnwind);

    GlobalVariable* cache = GetOrCreateGPUCache(m, lane);

    BasicBlock* entrybb = BasicBlock::Create(c, "Entry", f);
    BasicBlock* computebb = BasicBlock::Create(c, "Compute", f);
    BasicBlock* donebb = BasicBlock::Create(c, "Done", f);

    IRBuilder<> b(entrybb);
    LoadInst* cv = b.CreateLoad(i64, cache, "Cv");
    cv->setAlignment(Align(8));
    cv->setAtomic(AtomicOrdering::Monotonic);
    Value* hit = b.CreateICmpNE(cv, ConstantInt::get(i64, 0), "CvHit");
    b.CreateCondBr(hit, donebb, computebb);

    HelperScaffold s;
    s.Fn = f;
    s.EntryBB = entrybb;
    s.ComputeBB = computebb;
    s.DoneBB = donebb;
    s.CachedVal = cv;
    s.Cache = cache;
    return s;
}

void FinalizeHelper(HelperScaffold& s, IRBuilder<>& compb, Value* raw64)
{
    LLVMContext& c = s.Fn->getContext();
    Type* i64 = Type::getInt64Ty(c);

    Value* safe = EmitSentinelSafe(compb, raw64);
    StoreInst* st = compb.CreateStore(safe, s.Cache);
    st->setAlignment(Align(8));
    st->setAtomic(AtomicOrdering::Monotonic);
    BasicBlock* storebb = compb.GetInsertBlock();
    compb.CreateBr(s.DoneBB);

    IRBuilder<> db(s.DoneBB);
    PHINode* r = db.CreatePHI(i64, 2, "R");
    r->addIncoming(s.CachedVal, s.EntryBB);
    r->addIncoming(safe, storebb);
    db.CreateRet(r);
}

GlobalVariable* MakeGUIDConst(Module& m, StringRef name, const uint8_t (&bytes)[16])
{
    if (auto* ex = m.getGlobalVariable(name)) return ex;
    LLVMContext& c = m.getContext();
    ArrayType* arr16 = ArrayType::get(Type::getInt8Ty(c), 16);
    SmallVector<Constant*, 16> vals;
    for (uint8_t by : bytes)
        vals.push_back(ConstantInt::get(Type::getInt8Ty(c), by));
    auto* gv = new GlobalVariable(m, arr16, true, GlobalValue::PrivateLinkage, ConstantArray::get(arr16, vals), name);
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

void HoistAllocaToEntry(AllocaInst* a, BasicBlock* entrybb)
{
    if (a->getParent() == entrybb) return;
    a->moveBefore(&*entrybb->getFirstInsertionPt());
}

Value* EmitVtCall(IRBuilder<>& b, Value* thisptr, unsigned slot, FunctionType* fty, ArrayRef<Value*> args)
{
    LLVMContext& c = b.getContext();
    Type* ptrty = PointerType::get(c, 0);
    Type* i64 = Type::getInt64Ty(c);
    Value* vtbl = b.CreateLoad(ptrty, thisptr, "Vtbl");
    Value* slotptr = b.CreateGEP(ptrty, vtbl, ConstantInt::get(i64, (uint64_t)slot), "VtSlot");
    Value* fn = b.CreateLoad(ptrty, slotptr, "VtFn");
    SmallVector<Value*, 8> callargs;
    callargs.push_back(thisptr);
    for (Value* v : args) callargs.push_back(v);
    return b.CreateCall(fty, fn, callargs, "VtR");
}

Value* EmitFNVFoldU32(IRBuilder<>& b, Value* h, Value* v32)
{
    LLVMContext& c = b.getContext();
    Type* i64 = Type::getInt64Ty(c);
    Value* prime = ConstantInt::get(i64, FNVPrime);
    Value* v64 = b.CreateZExt(v32, i64);
    for (int i = 0; i < 4; ++i)
    {
        Value* shifted = (i == 0) ? v64 : b.CreateLShr(v64, ConstantInt::get(i64, (uint64_t)(i * 8)));
        Value* byte = b.CreateAnd(shifted, ConstantInt::get(i64, 0xFF));
        h = b.CreateXor(h, byte);
        h = b.CreateMul(h, prime);
    }
    return h;
}

Value* EmitVMemBucket(IRBuilder<>& b, Value* v64)
{
    LLVMContext& c = b.getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    Value* bucket = ConstantInt::get(i32, NumVMemEdges);
    for (unsigned i = NumVMemEdges; i-- > 0;)
    {
        Value* edge = ConstantInt::get(i64, VMemEdges[i]);
        Value* cmp = b.CreateICmpULT(v64, edge);
        bucket = b.CreateSelect(cmp, ConstantInt::get(i32, i), bucket);
    }
    return bucket;
}

Value* EmitSentinelSafe(IRBuilder<>& b, Value* h64)
{
    LLVMContext& c = b.getContext();
    Type* i64 = Type::getInt64Ty(c);
    Value* zero = ConstantInt::get(i64, 0);
    Value* allones = ConstantInt::get(i64, ~(uint64_t)0);
    Value* one = ConstantInt::get(i64, 1);
    Value* is0 = b.CreateICmpEQ(h64, zero);
    Value* isM1 = b.CreateICmpEQ(h64, allones);
    Value* bad = b.CreateOr(is0, isM1);
    return b.CreateSelect(bad, one, h64);
}

AdapterLoopOut EmitAdapterLoop(Module& m, Function* f, BasicBlock* prebb, Value* factory, FunctionType* enumfty, FunctionType* getdescfty, FunctionType* releasefty, const std::function<Value*(IRBuilder<>&, Value*, Value*, Value*)>& foldadapter)
{
    LLVMContext& c = f->getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    Type* i8 = Type::getInt8Ty(c);
    Type* ptrty = PointerType::get(c, 0);

    BasicBlock* loophdr = BasicBlock::Create(c, "ALHdr", f);
    BasicBlock* loopgood = BasicBlock::Create(c, "ALGood", f);
    BasicBlock* loopcont = BasicBlock::Create(c, "ALCont", f);
    BasicBlock* loopdone = BasicBlock::Create(c, "ALDone", f);

    IRBuilder<> p(prebb);
    AllocaInst* adapslot = p.CreateAlloca(ptrty, nullptr, "AdapSlot");
    adapslot->setAlignment(Align(8));
    ArrayType* descarrt = ArrayType::get(i8, DescAlloc);
    AllocaInst* descbuf = p.CreateAlloca(descarrt, nullptr, "DescBuf");
    descbuf->setAlignment(Align(8));
    HoistAllocaToEntry(adapslot, &f->getEntryBlock());
    HoistAllocaToEntry(descbuf, &f->getEntryBlock());
    p.CreateBr(loophdr);

    IRBuilder<> h(loophdr);
    PHINode* iphi = h.CreatePHI(i32, 2, "I");
    iphi->addIncoming(ConstantInt::get(i32, 0), prebb);
    PHINode* hphi = h.CreatePHI(i64, 2, "H");
    hphi->addIncoming(ConstantInt::get(i64, FNVInit), prebb);
    h.CreateStore(ConstantPointerNull::get(cast<PointerType>(ptrty)), adapslot);
    Value* enumhr = EmitVtCall(h, factory, VtEnumAdapters1, enumfty, {iphi, adapslot});
    Value* enumok = h.CreateICmpEQ(enumhr, ConstantInt::get(i32, 0), "EnOk");
    h.CreateCondBr(enumok, loopgood, loopdone);

    IRBuilder<> g(loopgood);
    Value* adap = g.CreateLoad(ptrty, adapslot, "Adap");
    Value* adapnn = g.CreateICmpNE(adap, ConstantPointerNull::get(cast<PointerType>(ptrty)));
    BasicBlock* adapokbb = BasicBlock::Create(c, "ALAok", f);
    BasicBlock* adapskipbb = loopcont;
    g.CreateCondBr(adapnn, adapokbb, adapskipbb);

    IRBuilder<> ao(adapokbb);
    Value* gdhr = EmitVtCall(ao, adap, VtGetDesc1, getdescfty, {descbuf});
    Value* gdok = ao.CreateICmpEQ(gdhr, ConstantInt::get(i32, 0), "GdOk");
    BasicBlock* foldbb = BasicBlock::Create(c, "ALFold", f);
    BasicBlock* relbb = BasicBlock::Create(c, "ALRel", f);
    ao.CreateCondBr(gdok, foldbb, relbb);

    IRBuilder<> fb(foldbb);
    Value* hnew = foldadapter(fb, adap, descbuf, hphi);
    fb.CreateBr(relbb);

    IRBuilder<> rb(relbb);
    PHINode* hafterfold = rb.CreatePHI(i64, 2, "HAf");
    hafterfold->addIncoming(hphi, adapokbb);
    hafterfold->addIncoming(hnew, foldbb);
    EmitVtCall(rb, adap, VtRelease, releasefty, {});
    rb.CreateBr(loopcont);

    IRBuilder<> lc(loopcont);
    PHINode* hcont = lc.CreatePHI(i64, 2, "HCont");
    hcont->addIncoming(hphi, loopgood);
    hcont->addIncoming(hafterfold, relbb);
    Value* inext = lc.CreateAdd(iphi, ConstantInt::get(i32, 1), "IN");
    Value* more = lc.CreateICmpULT(inext, ConstantInt::get(i32, MaxAdaptersProbe));
    lc.CreateCondBr(more, loophdr, loopdone);
    iphi->addIncoming(inext, loopcont);
    hphi->addIncoming(hcont, loopcont);

    IRBuilder<> d(loopdone);
    PHINode* hdone = d.CreatePHI(i64, 2, "HDone");
    hdone->addIncoming(hphi, loophdr);
    hdone->addIncoming(hcont, loopcont);

    AdapterLoopOut out;
    out.HFinal = hdone;
    out.EnumDoneBB = loopdone;
    return out;
}

Value* EmitPerAdapterFold(IRBuilder<>& b, Value* descbuf, Value* hacc, Value* extrau32)
{
    LLVMContext& c = b.getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    Type* i8 = Type::getInt8Ty(c);

    auto readu32 = [&](unsigned off, const char* name) -> Value*
    {
        Value* p = b.CreateGEP(i8, descbuf, ConstantInt::get(i64, (uint64_t)off), name);
        LoadInst* ld = b.CreateLoad(i32, p, name);
        ld->setAlignment(Align(1));
        return ld;
    };
    auto readu64 = [&](unsigned off, const char* name) -> Value*
    {
        Value* p = b.CreateGEP(i8, descbuf, ConstantInt::get(i64, (uint64_t)off), name);
        LoadInst* ld = b.CreateLoad(i64, p, name);
        ld->setAlignment(Align(1));
        return ld;
    };

    Value* ven = readu32(DescVendorId, "Ven");
    Value* dev = readu32(DescDeviceId, "Dev");
    Value* sub = readu32(DescSubSysId, "Sub");
    Value* rev = readu32(DescRevision, "Rev");
    Value* vram = readu64(DescVram, "Vram");
    Value* flg = readu32(DescFlags, "Flg");

    Value* vshl = b.CreateShl(ven, ConstantInt::get(i32, 16));
    Value* dmsk = b.CreateAnd(dev, ConstantInt::get(i32, 0xFFFF));
    Value* vendev = b.CreateOr(vshl, dmsk);

    Value* pa = ConstantInt::get(i64, FNVInit);
    pa = EmitFNVFoldU32(b, pa, vendev);
    pa = EmitFNVFoldU32(b, pa, sub);
    pa = EmitFNVFoldU32(b, pa, rev);
    pa = EmitFNVFoldU32(b, pa, EmitVMemBucket(b, vram));
    pa = EmitFNVFoldU32(b, pa, flg);
    if (extrau32) pa = EmitFNVFoldU32(b, pa, extrau32);

    return b.CreateXor(hacc, pa);
}

Function* EnsureHelperDXGI(Module& m)
{
    const std::string lane = "dxgi";
    const std::string fnname = "__lic_gpu_fp_" + lane;
    if (Function* ex = m.getFunction(fnname)) return ex;

    LLVMContext& c = m.getContext();
    IntegerType* i32 = Type::getInt32Ty(c);
    Type* ptrty = PointerType::get(c, 0);

    HelperScaffold s = BeginHelper(m, lane);

    FunctionType* cdfft = FunctionType::get(i32, {ptrty, ptrty}, false);
    FunctionCallee cdf = DeclImport(m, "CreateDXGIFactory1", cdfft);
    GlobalVariable* iid = MakeGUIDConst(m, "__lic_IID_IDXGIFactory1", IIDDXGIFactory1);

    FunctionType* enumft = FunctionType::get(i32, {ptrty, i32, ptrty}, false);
    FunctionType* getdescft = FunctionType::get(i32, {ptrty, ptrty}, false);
    FunctionType* relft = FunctionType::get(i32, {ptrty}, false);

    IRBuilder<> b(s.ComputeBB);
    AllocaInst* factslot = b.CreateAlloca(ptrty, nullptr, "FactSlot");
    factslot->setAlignment(Align(8));
    HoistAllocaToEntry(factslot, s.EntryBB);
    b.CreateStore(ConstantPointerNull::get(cast<PointerType>(ptrty)), factslot);
    Value* hr = b.CreateCall(cdf, {iid, factslot}, "CdfHr");
    Value* ok = b.CreateICmpEQ(hr, ConstantInt::get(i32, 0), "CdfOk");
    BasicBlock* enumbb = BasicBlock::Create(c, "CdfOkBB", s.Fn);
    BasicBlock* failbb = BasicBlock::Create(c, "CdfFailBB", s.Fn);
    b.CreateCondBr(ok, enumbb, failbb);

    IRBuilder<> fb(failbb);
    Value* failval = ConstantInt::get(Type::getInt64Ty(c), 1);

    IRBuilder<> eb(enumbb);
    Value* factory = eb.CreateLoad(ptrty, factslot, "Factory");

    AdapterLoopOut al = EmitAdapterLoop(m, s.Fn, enumbb, factory, enumft, getdescft, relft,
        [&](IRBuilder<>& fbld, Value*, Value* descbuf, Value* h)
        {
            return EmitPerAdapterFold(fbld, descbuf, h);
        });

    IRBuilder<> ad(al.EnumDoneBB);
    EmitVtCall(ad, factory, VtRelease, relft, {});

    BasicBlock* storemergebb = BasicBlock::Create(c, "Finalize", s.Fn);
    ad.CreateBr(storemergebb);
    fb.CreateBr(storemergebb);

    IRBuilder<> mg(storemergebb);
    PHINode* mergedh = mg.CreatePHI(Type::getInt64Ty(c), 2, "Merged");
    mergedh->addIncoming(al.HFinal, al.EnumDoneBB);
    mergedh->addIncoming(failval, failbb);

    FinalizeHelper(s, mg, mergedh);
    return s.Fn;
}

Function* EnsureHelperD3Dx(Module& m, bool d3d12)
{
    const std::string lane = d3d12 ? "d3d12" : "d3d11";
    const std::string fnname = "__lic_gpu_fp_" + lane;
    if (Function* ex = m.getFunction(fnname)) return ex;

    LLVMContext& c = m.getContext();
    IntegerType* i32 = Type::getInt32Ty(c);
    Type* ptrty = PointerType::get(c, 0);

    HelperScaffold s = BeginHelper(m, lane);

    FunctionType* cdfft = FunctionType::get(i32, {ptrty, ptrty}, false);
    FunctionCallee cdf = DeclImport(m, "CreateDXGIFactory1", cdfft);
    GlobalVariable* iidfac = MakeGUIDConst(m, "__lic_IID_IDXGIFactory1", IIDDXGIFactory1);
    GlobalVariable* iiddev = MakeGUIDConst(m, "__lic_IID_ID3D12Device", IIDD3D12Device);

    FunctionType* d11ft = FunctionType::get(i32, {ptrty, i32, ptrty, i32, ptrty, i32, i32, ptrty, ptrty, ptrty}, false);
    FunctionType* d12ft = FunctionType::get(i32, {ptrty, i32, ptrty, ptrty}, false);
    FunctionCallee d3d = d3d12 ? DeclImport(m, "D3D12CreateDevice", d12ft) : DeclImport(m, "D3D11CreateDevice", d11ft);

    FunctionType* enumft = FunctionType::get(i32, {ptrty, i32, ptrty}, false);
    FunctionType* getdescft = FunctionType::get(i32, {ptrty, ptrty}, false);
    FunctionType* relft = FunctionType::get(i32, {ptrty}, false);

    IRBuilder<> b(s.ComputeBB);
    AllocaInst* factslot = b.CreateAlloca(ptrty, nullptr, "FactSlot");
    factslot->setAlignment(Align(8));
    HoistAllocaToEntry(factslot, s.EntryBB);
    b.CreateStore(ConstantPointerNull::get(cast<PointerType>(ptrty)), factslot);

    AllocaInst* flarr = nullptr;
    AllocaInst* outfl = nullptr;
    if (!d3d12)
    {
        ArrayType* flarrt = ArrayType::get(i32, NumD3D11Levels);
        flarr = b.CreateAlloca(flarrt, nullptr, "FlArr");
        flarr->setAlignment(Align(4));
        HoistAllocaToEntry(flarr, s.EntryBB);
        for (unsigned i = 0; i < NumD3D11Levels; ++i)
        {
            Value* idx[2] = { ConstantInt::get(i32, 0), ConstantInt::get(i32, (uint32_t)i) };
            Value* ep = b.CreateInBoundsGEP(flarrt, flarr, idx, "FlE");
            b.CreateStore(ConstantInt::get(i32, D3D11LevelsProbe[i]), ep);
        }
        outfl = b.CreateAlloca(i32, nullptr, "FlOut");
        outfl->setAlignment(Align(4));
        HoistAllocaToEntry(outfl, s.EntryBB);
        b.CreateStore(ConstantInt::get(i32, 0), outfl);
    }

    Value* hr = b.CreateCall(cdf, {iidfac, factslot}, "CdfHr");
    Value* ok = b.CreateICmpEQ(hr, ConstantInt::get(i32, 0), "CdfOk");
    BasicBlock* enumbb = BasicBlock::Create(c, "CdfOkBB", s.Fn);
    BasicBlock* failbb = BasicBlock::Create(c, "CdfFailBB", s.Fn);
    b.CreateCondBr(ok, enumbb, failbb);

    IRBuilder<> fb(failbb);
    Value* failval = ConstantInt::get(Type::getInt64Ty(c), 1);

    IRBuilder<> eb(enumbb);
    Value* factory = eb.CreateLoad(ptrty, factslot, "Factory");

    AdapterLoopOut al = EmitAdapterLoop(m, s.Fn, enumbb, factory, enumft, getdescft, relft,
        [&](IRBuilder<>& fbld, Value* adap, Value* descbuf, Value* h)
        {
            Value* maxfl = nullptr;
            if (d3d12)
            {
                maxfl = ConstantInt::get(i32, 0);
                for (unsigned i = 0; i < NumD3D12Levels; ++i)
                {
                    uint32_t lv = D3D12LevelsProbe[i];
                    Value* lvv = ConstantInt::get(i32, lv);
                    Value* probehr = fbld.CreateCall(d3d, {adap, lvv, iiddev, ConstantPointerNull::get(cast<PointerType>(ptrty))}, "D12Hr");
                    Value* okprobe = fbld.CreateICmpSGE(probehr, ConstantInt::get(i32, 0), "D12Ok");
                    Value* zero = ConstantInt::get(i32, 0);
                    Value* havemax = fbld.CreateICmpNE(maxfl, zero);
                    Value* takethis = fbld.CreateAnd(fbld.CreateXor(havemax, ConstantInt::get(Type::getInt1Ty(c), 1)), okprobe);
                    maxfl = fbld.CreateSelect(takethis, lvv, maxfl, "D12Mf");
                }
            }
            else
            {
                Value* flarrptr = flarr;
                fbld.CreateStore(ConstantInt::get(i32, 0), outfl);
                Value* d11hr = fbld.CreateCall(d3d, { adap, ConstantInt::get(i32, D3DDriverTypeUnknown), ConstantPointerNull::get(cast<PointerType>(ptrty)), ConstantInt::get(i32, 0), flarrptr, ConstantInt::get(i32, (uint32_t)NumD3D11Levels), ConstantInt::get(i32, D3D11SDKVersion), ConstantPointerNull::get(cast<PointerType>(ptrty)), outfl, ConstantPointerNull::get(cast<PointerType>(ptrty)) }, "D11Hr");
                Value* okd11 = fbld.CreateICmpSGE(d11hr, ConstantInt::get(i32, 0), "D11Ok");
                Value* actual = fbld.CreateLoad(i32, outfl, "D11Fl");
                maxfl = fbld.CreateSelect(okd11, actual, ConstantInt::get(i32, 0), "D11Mf");
            }
            return EmitPerAdapterFold(fbld, descbuf, h, maxfl);
        });

    IRBuilder<> ad(al.EnumDoneBB);
    EmitVtCall(ad, factory, VtRelease, relft, {});

    BasicBlock* storemergebb = BasicBlock::Create(c, "Finalize", s.Fn);
    ad.CreateBr(storemergebb);
    fb.CreateBr(storemergebb);

    IRBuilder<> mg(storemergebb);
    PHINode* mergedh = mg.CreatePHI(Type::getInt64Ty(c), 2, "Merged");
    mergedh->addIncoming(al.HFinal, al.EnumDoneBB);
    mergedh->addIncoming(failval, failbb);
    FinalizeHelper(s, mg, mergedh);
    return s.Fn;
}

bool HasGPUAdapterAnnotation(Function& f)
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
        if (cds->getAsCString() == "GPUAdapter") return true;
    }
    return false;
}