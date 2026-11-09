#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "Gadgets.h"
#include "Imports.h"
#include "LicensingPass.h"

#include "DLLHelper/DLLGrabberUtility.h"
#include "DLLHelper/OfficialDLLDownloader.h"
#include "DLLHelper/DLLExportGrabber.h"

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace llvm;

static constexpr const char* SystemDir = "C:\\Windows\\System32";
static constexpr unsigned StashOffset = 0x200;
static constexpr unsigned XrefThresh = 16;
static constexpr unsigned MaxPerFn = 20;
static constexpr unsigned MaxMemPerFn = 8;
static constexpr unsigned MemModBudget = 2048;
static constexpr uint64_t SeedSalt = 0x9E3779B9C0AFEE11ULL;
static constexpr size_t MaxGadgetBytes = 16;

static bool HasAnnotation(Function& f, StringRef tag)
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
        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;
        auto* cds = dyn_cast<ConstantDataArray>(strgv->getInitializer());
        if (!cds || !cds->isCString()) continue;
        if (cds->getAsCString() == tag) return true;
    }
    return false;
}

static uint64_t Mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static uint64_t ModuleNameHash = 0;
static uint64_t SiteCounter = 0;

static uint64_t NextSiteId()
{
    const uint64_t ord = ++SiteCounter;
    return Mix64(ModuleNameHash ^ (ord * 0x9E3779B97F4A7C15ULL));
}

struct JmpGadget
{
    uint32_t RVA;
    uint8_t Reg;
    uint8_t ModIdx;
    uint8_t Len;
};

struct MemGadget
{
    uint32_t RVA;
    uint8_t Dst;
    uint8_t Base;
    int32_t Disp;
    uint8_t OpSize;
    uint8_t ModIdx;
    uint8_t Len;
};

struct DllModule
{
    std::string NameLower;
    std::wstring CanonicalPath;
    uint32_t SizeOfImage;
    uint8_t ModIdx;
    uint64_t NameHash;
};

static std::vector<DllModule> DllModules;
static std::vector<JmpGadget> JmpPool;
static std::vector<MemGadget> LoadPool;
static std::vector<MemGadget> StorePool;

static uint64_t HashModuleUtf16Upper(const std::string& asciinamelower)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : asciinamelower)
    {
        uint64_t ch = (uint64_t)(uint8_t)c;
        if (ch >= 'a' && ch <= 'z') ch -= 0x20;
        h ^= ch;
        h *= 0x100000001b3ULL;
    }
    return h;
}

static bool ScanDllFile(const std::wstring& path, uint8_t modidx, uint32_t& outsizeofimage)
{
    outsizeofimage = 0;
    std::ifstream f(path.c_str(), std::ios::binary | std::ios::ate);
    if (!f) return false;
    const std::streamoff sz = f.tellg();
    if (sz < 0x400) return false;
    std::vector<uint8_t> img((size_t)sz);
    f.seekg(0);
    f.read((char*)img.data(), sz);
    if (!f) return false;

    const uint32_t lfanew = *(const uint32_t*)(img.data() + 0x3C);
    if (lfanew + 0x18 > img.size()) return false;
    if (*(const uint32_t*)(img.data() + lfanew) != 0x00004550) return false;
    const uint8_t* fh = img.data() + lfanew + 4;
    const uint16_t nsec = *(const uint16_t*)(fh + 0x02);
    const uint16_t optsz = *(const uint16_t*)(fh + 0x10);
    const uint8_t* sec = fh + 0x14 + optsz;
    if (sec + (size_t)nsec * 40 > img.data() + img.size()) return false;
    if (optsz >= 0x3C)
    {
        const uint8_t* opt = fh + 0x14;
        if (*(const uint16_t*)opt == 0x20B) outsizeofimage = *(const uint32_t*)(opt + 0x38);
    }

    struct Range { uint32_t S, E; };
    std::vector<Range> relocs;
    if (optsz >= 0x90)
    {
        const uint8_t* opt = fh + 0x14;
        const uint32_t rrva = *(const uint32_t*)(opt + 0x88);
        const uint32_t rsz = *(const uint32_t*)(opt + 0x8C);
        if (rrva && rsz)
        {
            const uint8_t* s2 = fh + 0x14 + optsz;
            uint32_t roff = 0;
            for (uint16_t s = 0; s < nsec; ++s, s2 += 40)
            {
                const uint32_t va = *(const uint32_t*)(s2 + 0x0C);
                const uint32_t rs = *(const uint32_t*)(s2 + 0x10);
                if (rrva >= va && rrva < va + rs)
                {
                    roff = *(const uint32_t*)(s2 + 0x14) + (rrva - va);
                    break;
                }
            }
            uint32_t off = roff;
            const uint32_t end = (uint32_t)std::min<size_t>((size_t)off + rsz, img.size());
            while (off && off + 8 <= end)
            {
                const uint32_t blkva = *(const uint32_t*)(img.data() + off);
                const uint32_t blksz = *(const uint32_t*)(img.data() + off + 4);
                if (blksz < 8 || off + blksz > img.size()) break;
                const uint32_t n = (blksz - 8) / 2;
                for (uint32_t i = 0; i < n; ++i)
                {
                    const uint16_t e = *(const uint16_t*)(img.data() + off + 8 + i * 2);
                    if ((e >> 12) == 0) continue;
                    const uint32_t rva = blkva + (e & 0x0FFF);
                    relocs.push_back({rva, rva + 8});
                }
                off += blksz;
            }
        }
    }
    auto overlapsreloc = [&](uint32_t rva, uint32_t len)
    {
        for (const Range& r : relocs)
            if (rva < r.E && rva + len > r.S) return true;
        return false;
    };

    const uint8_t* seciter = fh + 0x14 + optsz;
    for (uint16_t s = 0; s < nsec; ++s, seciter += 40)
    {
        const uint32_t virtaddr = *(const uint32_t*)(seciter + 0x0C);
        const uint32_t rawsz = *(const uint32_t*)(seciter + 0x10);
        const uint32_t rawptr = *(const uint32_t*)(seciter + 0x14);
        const uint32_t chars = *(const uint32_t*)(seciter + 0x24);
        if (!(chars & 0x20000000)) continue;
        if (rawptr >= img.size()) continue;
        const size_t avail = std::min<size_t>(rawsz, img.size() - rawptr);
        const uint8_t* b = img.data() + rawptr;

        for (size_t p = 0; p + 2 < avail; ++p)
        {
            const uint8_t b0 = b[p], b1 = b[p + 1];

            auto recordjmp = [&](uint8_t regcode, uint32_t glen)
            {
                if (regcode != 0 && regcode != 10 && regcode != 11) return;
                const uint32_t rva = virtaddr + (uint32_t)p;
                if (overlapsreloc(rva, glen)) return;
                JmpPool.push_back({rva, regcode, modidx, (uint8_t)glen});
            };

            if (b0 == 0xFF && b1 >= 0xE0 && b1 <= 0xE7)
            {
                recordjmp((uint8_t)(b1 & 7), 2);
            }
            else if (b0 == 0x41 && p + 2 < avail && b[p + 1] == 0xFF && b[p + 2] >= 0xE0 && b[p + 2] <= 0xE7)
            {
                recordjmp((uint8_t)((b[p + 2] & 7) | 8), 3);
            }

            const uint32_t rpfx = (b0 >= 0x40 && b0 <= 0x4F) ? 1u : 0u;
            const uint8_t rex = rpfx ? b0 : 0;
            if (p + rpfx + 2 >= avail) continue;
            const uint8_t op = rpfx ? b1 : b0;
            const uint8_t mrm = b[p + rpfx + 1];
            if (op != 0x8B && op != 0x89) continue;
            const uint8_t mod = (uint8_t)(mrm >> 6);
            const uint8_t rm = (uint8_t)(mrm & 7);
            if (mod == 3) continue;
            if (rm == 4) continue;
            if (mod == 0 && rm == 5) continue;

            uint32_t dispbytes = (mod == 1) ? 1 : (mod == 2) ? 4 : 0;
            const uint32_t hdr = rpfx + 2;
            const uint32_t total = hdr + dispbytes + 1;
            if (p + total > avail) continue;
            if (b[p + hdr + dispbytes] != 0xC3) continue;

            const uint8_t regcode = (uint8_t)(((mrm >> 3) & 7) | ((rex & 0x04) ? 8 : 0));
            const uint8_t basecode = (uint8_t)((mrm & 7) | ((rex & 0x01) ? 8 : 0));
            if (regcode == 4 || basecode == 4) continue;
            if (regcode == 5 || basecode == 5) continue;

            int32_t disp = 0;
            if (dispbytes == 1) disp = (int8_t)b[p + hdr];
            else if (dispbytes == 4)
            {
                int32_t t;
                std::memcpy(&t, b + p + hdr, 4);
                disp = t;
            }
            const uint8_t opsize = (rex & 0x08) ? 8 : 4;
            const uint32_t rva = virtaddr + (uint32_t)p;
            if (overlapsreloc(rva, total)) continue;

            MemGadget g{rva, regcode, basecode, disp, opsize, modidx, (uint8_t)total};
            if (op == 0x8B) LoadPool.push_back(g);
            else StorePool.push_back(g);
        }
    }
    return true;
}

static bool HarvestDll(const std::string& nmlower)
{
#ifdef _WIN32
    for (const DllModule& m : DllModules)
        if (m.NameLower == nmlower) return true;

    std::filesystem::path syspath(SystemDir);
    syspath /= nmlower;

    DLLGrabberUtility::DllIdentity id;
    std::wstring err;
    if (!DLLGrabberUtility::Instance().GrabIdentity(syspath.wstring(), id, err)) return false;
    OfficialDllDownloader::DownloadResult dr;
    if (!OfficialDllDownloader::Instance().TryGetCachedDll(id.DllName, id.TimeDateStamp, id.SizeOfImage, dr) || !dr.Success)
    {
        if (!OfficialDllDownloader::Instance().DownloadDll(id.DllName, id.TimeDateStamp, id.SizeOfImage, dr) || !dr.Success) return false;
    }

    DllModule mod;
    mod.NameLower = nmlower;
    mod.CanonicalPath = dr.OutputPath;
    mod.SizeOfImage = id.SizeOfImage;
    mod.ModIdx = (uint8_t)DllModules.size();
    mod.NameHash = HashModuleUtf16Upper(nmlower);
    DllModules.push_back(mod);

    uint32_t soi = 0;
    if (!ScanDllFile(mod.CanonicalPath, mod.ModIdx, soi)) return false;
    return true;
#else
    (void)nmlower;
    return false;
#endif
}

struct UsedGadget
{
    uint8_t ModIdx;
    uint32_t RVA;
    uint8_t Len;
    std::array<uint8_t, MaxGadgetBytes> Bytes;
};
static std::vector<UsedGadget> UsedGadgets;
static DenseMap<Function*, DenseSet<uint8_t>> SlotFillDone;
static std::string NameSuffix;

static std::string RopfSym(const char* stem)
{
    return std::string(stem) + "_" + NameSuffix;
}

static void AnchorRopfGV(Module& m, GlobalVariable* gv)
{
    gv->setLinkage(GlobalValue::ExternalLinkage);
    gv->setVisibility(GlobalValue::HiddenVisibility);
    gv->setDSOLocal(true);
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    appendToCompilerUsed(m, {gv});
}

static GlobalVariable* GetOrCreateSlotsGV(Module& m, size_t nmodules)
{
    const std::string kname = RopfSym("__ropf_slots");
    if (auto* gv = m.getGlobalVariable(kname)) return gv;
    LLVMContext& c = m.getContext();
    Type* i64 = Type::getInt64Ty(c);
    ArrayType* arrt = ArrayType::get(i64, nmodules);
    auto* gv = new GlobalVariable(m, arrt, false, GlobalValue::ExternalLinkage, ConstantAggregateZero::get(arrt), kname);
    gv->setAlignment(Align(8));
    AnchorRopfGV(m, gv);
    return gv;
}

static GlobalVariable* GetOrCreateDllNameGV(Module& m, const std::string& nm)
{
    const std::string gvname = RopfSym("__ropf_name") + "_" + std::to_string(std::hash<std::string>{}(nm));
    if (auto* gv = m.getGlobalVariable(gvname)) return gv;
    LLVMContext& c = m.getContext();
    Constant* init = ConstantDataArray::getString(c, nm, true);
    auto* gv = new GlobalVariable(m, init->getType(), true, GlobalValue::PrivateLinkage, init, gvname);
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

struct Dispatch
{
    uint32_t Enc;
    uint32_t Key;
    uint64_t SiteId;
    uint8_t ModIdx;
    uint32_t GadgetRVA;
};

static Dispatch MakeDispatch(uint8_t modidx, uint32_t gadgetrva)
{
    Dispatch d;
    d.SiteId = NextSiteId();
    d.ModIdx = modidx;
    d.GadgetRVA = gadgetrva;
    const uint64_t mix = Mix64(SeedSalt ^ d.SiteId ^ ((uint64_t)modidx << 32) ^ (uint64_t)gadgetrva);
    d.Key = (uint32_t)(mix ^ (mix >> 32));
    d.Enc = (uint32_t)gadgetrva ^ d.Key;
    return d;
}

static void RecordUsed(uint8_t modidx, uint32_t rva, uint8_t len)
{
    UsedGadget ug{};
    ug.ModIdx = modidx;
    ug.RVA = rva;
    ug.Len = len;
    ug.Bytes.fill(0);
    UsedGadgets.push_back(ug);
}

static void TagPhase3(Instruction* i)
{
    LLVMContext& c = i->getContext();
    i->setMetadata("lic.phase1", MDNode::get(c, {MDString::get(c, "p1")}));
    i->setMetadata("lic.rop", MDNode::get(c, {MDString::get(c, "p3")}));
}

static uint8_t PickScratch(std::initializer_list<uint8_t> forbidden)
{
    for (uint8_t cand : {(uint8_t)0, (uint8_t)10, (uint8_t)11})
    {
        bool bad = false;
        for (uint8_t f : forbidden) if (f == cand) { bad = true; break; }
        if (!bad) return cand;
    }
    return 0xFF;
}

static const char* RegName64(uint8_t code)
{
    static const char* k[] = { "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi", "r8","r9","r10","r11","r12","r13","r14","r15" };
    return k[code & 15];
}

static const char* RegName32(uint8_t code)
{
    static const char* k[] = { "eax","ecx","edx","ebx","esp","ebp","esi","edi", "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d" };
    return k[code & 15];
}

static std::string EmitStashSaveOpen(unsigned preshift, const char* stashreg = "rbx")
{
    const unsigned off = StashOffset - preshift - 8;
    std::ostringstream o;
    o << "pushq %" << stashreg << "\n\t" << "movq -" << off << "(%rsp), %" << stashreg << "\n\t";
    return o.str();
}

static std::string EmitStashRestoreClose(unsigned preshift, const char* stashreg = "rbx")
{
    const unsigned off = StashOffset - preshift - 8;
    std::ostringstream o;
    o << "movq %" << stashreg << ", %" << stashreg << "\n\t";
    o.str("");
    o << "movq %" << stashreg << ", -" << off << "(%rsp)\n\t" << "popq %" << stashreg << "\n\t";
    return o.str();
}

static const char* PickStashReg(uint8_t avoida, uint8_t avoidb)
{
    static const struct { uint8_t Code; const char* Name; } cands[] =
    {
        {3,"rbx"}, {14,"r14"}, {15,"r15"}, {12,"r12"},
        {13,"r13"}, {7,"rdi"}, {6,"rsi"}, {5,"rbp"},
    };
    for (const auto& c : cands)
        if (c.Code != avoida && c.Code != avoidb) return c.Name;
    return nullptr;
}

static void EnsureSlotFilled(Function* f, GlobalVariable* slotsgv, uint8_t modidx)
{
    auto& done = SlotFillDone[f];
    if (!done.insert(modidx).second) return;

    LLVMContext& c = f->getContext();
    BasicBlock& entry = f->getEntryBlock();
    IRBuilder<> b(&entry, entry.getFirstInsertionPt());

    FunctionCallee gmh = DeclGetModuleHandleA(*f->getParent());
    FunctionType* llaft = FunctionType::get(PointerType::get(c, 0), {PointerType::get(c, 0)}, false);
    FunctionCallee lla = f->getParent()->getOrInsertFunction("LoadLibraryA", llaft);
    if (auto* lf = dyn_cast<Function>(lla.getCallee()))
    {
        lf->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
        lf->setLinkage(GlobalValue::ExternalLinkage);
    }

    Type* i64 = Type::getInt64Ty(c);
    Type* ptrty = PointerType::get(c, 0);
    Constant* nullptrv = ConstantPointerNull::get(cast<PointerType>(ptrty));

    const DllModule& md = DllModules[modidx];
    GlobalVariable* namegv = GetOrCreateDllNameGV(*f->getParent(), md.NameLower);

    Value* h0 = b.CreateCall(gmh, {namegv}, "RopfPfH0");
    Value* nz = b.CreateICmpNE(h0, nullptrv, "RopfPfHok");

    BasicBlock* curbb = b.GetInsertBlock();
    BasicBlock* bbtail = curbb->splitBasicBlock(b.GetInsertPoint(), "RopfPfAfter");
    BasicBlock* bbll = BasicBlock::Create(c, "RopfPfLl", f, bbtail);
    curbb->getTerminator()->eraseFromParent();
    IRBuilder<>(curbb).CreateCondBr(nz, bbtail, bbll);

    IRBuilder<> bl(bbll);
    Value* h1 = bl.CreateCall(lla, {namegv}, "RopfPfH1");
    bl.CreateBr(bbtail);

    IRBuilder<> bt(bbtail, bbtail->getFirstInsertionPt());
    PHINode* h = bt.CreatePHI(ptrty, 2, "RopfPfH");
    h->addIncoming(h0, curbb);
    h->addIncoming(h1, bbll);
    Value* hi = bt.CreatePtrToInt(h, i64, "RopfPfHi");
    Value* idx[2] = { ConstantInt::get(Type::getInt32Ty(c), 0), ConstantInt::get(Type::getInt32Ty(c), (uint32_t)modidx) };
    Value* slot = bt.CreateGEP(slotsgv->getValueType(), slotsgv, idx, "RopfPfSlot");
    bt.CreateStore(hi, slot);
}

static bool TryEmitCallSite(CallBase* cb)
{
    Value* callee = cb->getCalledOperand();
    if (!callee) return false;
    auto* i2p = dyn_cast<IntToPtrInst>(callee);
    if (!i2p) return false;
    if (!i2p->getMetadata("lic.phase1")) return false;
    if (isa<InvokeInst>(cb)) return false;
    if (JmpPool.empty()) return false;

    const uint64_t sid = NextSiteId();
    std::mt19937_64 rng(SeedSalt ^ sid ^ 0xCA11B0BAULL);
    const JmpGadget& g = JmpPool[rng() % JmpPool.size()];
    const uint8_t rt = g.Reg;
    const uint8_t scr = PickScratch({rt});
    if (scr == 0xFF) return false;

    const Dispatch d = MakeDispatch(g.ModIdx, g.RVA);

    Function* parent = cb->getFunction();
    LLVMContext& c = parent->getContext();
    IRBuilder<> b(cb);

    EnsureSlotFilled(parent, GetOrCreateSlotsGV(*parent->getParent(), DllModules.size()), g.ModIdx);

    Type* rett = cb->getType();
    const bool hasret = !rett->isVoidTy();

    Value* fpi64 = nullptr;
    if (Value* src = i2p->getOperand(0))
        if (src->getType()->isIntegerTy(64)) fpi64 = src;
    if (!fpi64) fpi64 = b.CreatePtrToInt(callee, Type::getInt64Ty(c));

    const unsigned nargs = cb->arg_size();
    static const char* const intregs[4] = {"{rcx}","{rdx}","{r8}","{r9}"};
    static const char* const floatregs[4] = {"{xmm0}","{xmm1}","{xmm2}","{xmm3}"};
    if (nargs > 4) return false;
    if (cb->getFunctionType()->isVarArg()) return false;

    uint8_t fpreg = 0xFF;
    for (uint8_t cand : {(uint8_t)0, (uint8_t)10, (uint8_t)11})
        if (cand != rt && cand != scr) { fpreg = cand; break; }
    if (fpreg == 0xFF) return false;
    const char* fpregname = RegName64(fpreg);

    SmallVector<Value*, 8> ins;
    SmallVector<Type*, 8> intys;
    std::string cons;

    if (hasret)
    {
        if (rett->isFloatingPointTy()) cons = "={xmm0},";
        else if (rett->isIntegerTy() || rett->isPointerTy()) cons = "={rax},";
        else return false;
    }

    cons += "{";
    cons += fpregname;
    cons += "},";
    ins.push_back(fpi64);
    intys.push_back(Type::getInt64Ty(c));

    for (unsigned i = 0; i < nargs; ++i)
    {
        Value* a = cb->getArgOperand(i);
        Type* t = a->getType();
        if (t->isPointerTy())
        {
            a = b.CreatePtrToInt(a, Type::getInt64Ty(c));
            t = Type::getInt64Ty(c);
        }
        if (t->isIntegerTy())
        {
            if (t->getIntegerBitWidth() < 64)
            {
                a = b.CreateZExt(a, Type::getInt64Ty(c));
                t = Type::getInt64Ty(c);
            }
            cons += intregs[i];
            cons += ",";
        }
        else if (t->isFloatingPointTy())
        {
            cons += floatregs[i];
            cons += ",";
        }
        else
        {
            return false;
        }
        ins.push_back(a);
        intys.push_back(t);
    }

    std::ostringstream asmt;
    constexpr unsigned preshift = 8u;
    asmt << "pushfq\n\t";
    const char* stashrega = PickStashReg(0xFE, 0xFE);
    asmt << EmitStashSaveOpen(preshift, stashrega);
    asmt << "movq %" << fpregname << ", %" << RegName64(rt) << "\n\t";
    asmt << "movabsq $$" << (unsigned long long)d.Enc << ", %" << RegName64(scr) << "\n\t";
    asmt << "xorl $$" << (unsigned)d.Key << ", %" << RegName32(scr) << "\n\t";
    asmt << "addq " << RopfSym("__ropf_slots") << "+" << ((unsigned)d.ModIdx * 8) << "(%rip), %" << RegName64(scr) << "\n\t";
    asmt << "callq *%" << RegName64(scr) << "\n\t";
    asmt << EmitStashRestoreClose(preshift, stashrega);
    asmt << "popfq";

    cons += "~{rsi},~{rdi},~{xmm4},~{xmm5},~{xmm6},~{xmm7},~{xmm8},~{xmm9},~{xmm10},~{xmm11},~{xmm12},~{xmm13},~{xmm14},~{xmm15},~{memory},~{cc},~{dirflag},~{fpsr}";
    if (!hasret || !rett->isFloatingPointTy())
    {
        cons += ",~{xmm0},~{xmm1},~{xmm2},~{xmm3}";
    }
    const bool raxasoutput = hasret && (rett->isIntegerTy() || rett->isPointerTy());
    if (!raxasoutput && fpreg != 0) cons += ",~{rax}";
    if (fpreg != 10) cons += ",~{r10}";
    if (fpreg != 11) cons += ",~{r11}";
    for (unsigned i = nargs; i < 4; ++i) cons += (std::string(",~") + intregs[i]);

    Type* asmrett = rett;
    if (hasret && (rett->isIntegerTy() || rett->isPointerTy())) asmrett = Type::getInt64Ty(c);
    FunctionType* iaft = FunctionType::get(hasret ? asmrett : Type::getVoidTy(c), intys, false);
    InlineAsm* ia = InlineAsm::get(iaft, asmt.str(), cons, true, false, InlineAsm::AD_ATT);
    CallInst* newcall = b.CreateCall(ia, ins);
    newcall->setDebugLoc(cb->getDebugLoc());
    TagPhase3(newcall);

    if (hasret)
    {
        Value* result = newcall;
        if (rett->isPointerTy()) result = b.CreateIntToPtr(result, rett);
        else if (rett->isIntegerTy() && rett->getIntegerBitWidth() < 64) result = b.CreateTrunc(result, rett);
        cb->replaceAllUsesWith(result);
    }
    cb->eraseFromParent();

    RecordUsed(g.ModIdx, g.RVA, g.Len);
    return true;
}

static bool TryEmitLoadSite(LoadInst* li)
{
    if (li->isVolatile() || li->isAtomic()) return false;
    Type* valt = li->getType();
    unsigned bits = 0;
    if (valt->isIntegerTy()) bits = valt->getIntegerBitWidth();
    else if (valt->isPointerTy()) bits = 64;
    else return false;
    if (bits != 32 && bits != 64) return false;
    const uint8_t width = (uint8_t)(bits / 8);

    std::vector<const MemGadget*> ok;
    for (const MemGadget& g : LoadPool)
        if (g.OpSize == width && g.Dst != g.Base) ok.push_back(&g);
    if (ok.empty()) return false;
    const uint64_t sid = NextSiteId();
    std::mt19937_64 rng(SeedSalt ^ sid ^ 0xBEEFULL);
    const MemGadget& g = *ok[rng() % ok.size()];

    const Dispatch d = MakeDispatch(g.ModIdx, g.RVA);

    Function* parent = li->getFunction();
    LLVMContext& c = parent->getContext();
    IRBuilder<> b(li);

    EnsureSlotFilled(parent, GetOrCreateSlotsGV(*parent->getParent(), DllModules.size()), g.ModIdx);

    Value* addri64 = b.CreatePtrToInt(li->getPointerOperand(), Type::getInt64Ty(c));

    const uint8_t basereg = g.Base;
    const uint8_t dstreg = g.Dst;
    const uint8_t scr = PickScratch({basereg, dstreg});
    if (scr == 0xFF) return false;

    const std::string dstcons = std::string("={") + RegName64(dstreg) + "}";
    const std::string basecons = std::string("{") + RegName64(basereg) + "}";

    const char* stashregb = PickStashReg(basereg, dstreg);
    const bool dostashb = stashregb != nullptr;

    std::ostringstream asmt;
    constexpr unsigned preshiftb = 8u;
    asmt << "pushfq\n\t";
    if (dostashb) asmt << EmitStashSaveOpen(preshiftb, stashregb);
    if (g.Disp != 0)
    {
        asmt << "leaq " << (-(int64_t)g.Disp) << "(%" << RegName64(basereg) << "), %" << RegName64(basereg) << "\n\t";
    }
    asmt << "movabsq $$" << (unsigned long long)d.Enc << ", %" << RegName64(scr) << "\n\t";
    asmt << "xorl $$" << (unsigned)d.Key << ", %" << RegName32(scr) << "\n\t";
    asmt << "addq " << RopfSym("__ropf_slots") << "+" << ((unsigned)d.ModIdx * 8) << "(%rip), %" << RegName64(scr) << "\n\t";
    asmt << "callq *%" << RegName64(scr) << "\n\t";
    if (dostashb) asmt << EmitStashRestoreClose(preshiftb, stashregb);
    asmt << "popfq";

    std::string cons = dstcons + "," + basecons + ",~{memory},~{cc},~{dirflag},~{fpsr}";
    if (scr != dstreg && scr != basereg) cons += (std::string(",~{") + RegName64(scr) + "}");

    FunctionType* iaft = FunctionType::get(Type::getInt64Ty(c), {Type::getInt64Ty(c)}, false);
    InlineAsm* ia = InlineAsm::get(iaft, asmt.str(), cons, true, false, InlineAsm::AD_ATT);
    CallInst* ac = b.CreateCall(ia, {addri64});
    ac->setDebugLoc(li->getDebugLoc());
    TagPhase3(ac);

    Value* result = ac;
    if (width == 4) result = b.CreateTrunc(result, Type::getInt32Ty(c));
    if (valt->isPointerTy()) result = b.CreateIntToPtr(result, valt);

    li->replaceAllUsesWith(result);
    li->eraseFromParent();

    RecordUsed(g.ModIdx, g.RVA, g.Len);
    return true;
}

static bool TryEmitStoreSite(StoreInst* si)
{
    if (si->isVolatile() || si->isAtomic()) return false;
    Value* val = si->getValueOperand();
    Type* valt = val->getType();
    unsigned bits = 0;
    if (valt->isIntegerTy()) bits = valt->getIntegerBitWidth();
    else if (valt->isPointerTy()) bits = 64;
    else return false;
    if (bits != 32 && bits != 64) return false;
    const uint8_t width = (uint8_t)(bits / 8);

    std::vector<const MemGadget*> ok;
    for (const MemGadget& g : StorePool)
        if (g.OpSize == width && g.Dst != g.Base) ok.push_back(&g);
    if (ok.empty()) return false;

    const uint64_t sid = NextSiteId();
    std::mt19937_64 rng(SeedSalt ^ sid ^ 0xDEADULL);
    std::vector<const MemGadget*> ok2;
    for (const MemGadget* gp : ok)
        if (PickScratch({gp->Dst, gp->Base}) != 0xFF) ok2.push_back(gp);
    if (ok2.empty()) return false;
    const MemGadget& g = *ok2[rng() % ok2.size()];

    const uint8_t srcreg = g.Dst;
    const uint8_t basereg = g.Base;
    const uint8_t scr = PickScratch({srcreg, basereg});

    const Dispatch d = MakeDispatch(g.ModIdx, g.RVA);

    Function* parent = si->getFunction();
    LLVMContext& c = parent->getContext();
    IRBuilder<> b(si);

    EnsureSlotFilled(parent, GetOrCreateSlotsGV(*parent->getParent(), DllModules.size()), g.ModIdx);

    Value* addri64 = b.CreatePtrToInt(si->getPointerOperand(), Type::getInt64Ty(c));
    Value* vali64;
    if (valt->isPointerTy()) vali64 = b.CreatePtrToInt(val, Type::getInt64Ty(c));
    else if (valt->isIntegerTy(64)) vali64 = val;
    else vali64 = b.CreateZExt(val, Type::getInt64Ty(c));

    const std::string basecons = std::string("{") + RegName64(basereg) + "}";
    const std::string srccons = std::string("{") + RegName64(srcreg) + "}";

    const char* stashregc = PickStashReg(basereg, srcreg);
    const bool dostashc = stashregc != nullptr;

    std::ostringstream asmt;
    constexpr unsigned preshiftc = 8u;
    asmt << "pushfq\n\t";
    if (dostashc) asmt << EmitStashSaveOpen(preshiftc, stashregc);
    if (g.Disp != 0)
    {
        asmt << "leaq " << (-(int64_t)g.Disp) << "(%" << RegName64(basereg) << "), %" << RegName64(basereg) << "\n\t";
    }
    asmt << "movabsq $$" << (unsigned long long)d.Enc << ", %" << RegName64(scr) << "\n\t";
    asmt << "xorl $$" << (unsigned)d.Key << ", %" << RegName32(scr) << "\n\t";
    asmt << "addq " << RopfSym("__ropf_slots") << "+" << ((unsigned)d.ModIdx * 8) << "(%rip), %" << RegName64(scr) << "\n\t";
    asmt << "callq *%" << RegName64(scr) << "\n\t";
    if (dostashc) asmt << EmitStashRestoreClose(preshiftc, stashregc);
    asmt << "popfq";

    std::string cons = basecons + "," + srccons + ",~{memory},~{cc},~{dirflag},~{fpsr}";
    cons += (std::string(",~{") + RegName64(scr) + "}");

    FunctionType* iaft = FunctionType::get(Type::getVoidTy(c), {Type::getInt64Ty(c), Type::getInt64Ty(c)}, false);
    InlineAsm* ia = InlineAsm::get(iaft, asmt.str(), cons, true, false, InlineAsm::AD_ATT);
    CallInst* ac = b.CreateCall(ia, {addri64, vali64});
    ac->setDebugLoc(si->getDebugLoc());
    TagPhase3(ac);

    si->eraseFromParent();
    RecordUsed(g.ModIdx, g.RVA, g.Len);
    return true;
}

static constexpr uint64_t FNV1a64(const char* s)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    while (*s)
    {
        h ^= (uint8_t)(*s);
        h *= 0x100000001b3ULL;
        ++s;
    }
    return h;
}

static uint64_t FNV1a64Range(StringRef s)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : s)
    {
        h ^= (uint8_t)c;
        h *= 0x100000001b3ULL;
    }
    return h;
}

static bool IsCRTLikeName(StringRef name)
{
    if (name.starts_with("__scrt_")) return true;
    if (name.starts_with("__security_")) return true;
    if (name.starts_with("__report_")) return true;
    if (name.starts_with("__raise_")) return true;
    if (name.starts_with("_initterm")) return true;
    if (name.starts_with("__std_")) return true;
    if (name.starts_with("_std_")) return true;
    if (name.starts_with("__ms_v")) return true;
    if (name.starts_with("_vsnprintf")) return true;
    if (name.starts_with("_vsprintf")) return true;
    if (name.starts_with("_vprintf")) return true;
    if (name.starts_with("_snprintf")) return true;
    if (name.starts_with("_sprintf")) return true;
    if (name.starts_with("_RTC_")) return true;
    if (name.starts_with("__RTC_")) return true;
    if (name.starts_with("__GSHandlerCheck")) return true;
    if (name.starts_with("__gs_")) return true;
    if (name.starts_with("__chkstk")) return true;
    if (name.starts_with("__alloca_probe")) return true;
    if (name.starts_with("__stdio_")) return true;
    if (name.starts_with("__dyn_tls_")) return true;
    if (name.starts_with("_tls_start")) return true;
    if (name.starts_with("_tls_end")) return true;
    if (name.starts_with("pre_c_init")) return true;
    if (name.starts_with("_pre_cpp_init")) return true;
    if (name.starts_with("??_C@")) return true;
    if (name.starts_with("??_R")) return true;
    if (name.starts_with("__ropf_")) return true;
    if (name.starts_with("__lic_")) return true;

    switch (FNV1a64Range(name))
    {
        case FNV1a64("_cexit"):
        case FNV1a64("__onexit"):
        case FNV1a64("__xmainret"):
        case FNV1a64("__xcptfilter"):
        case FNV1a64("_C_specific_handler"):
        case FNV1a64("__C_specific_handler"):
        case FNV1a64("__CxxFrameHandler"):
        case FNV1a64("_setjmp"):
        case FNV1a64("_longjmp"):
        case FNV1a64("_except_handler"):
        case FNV1a64("??_7"):
        case FNV1a64("??_8"):
        case FNV1a64("??_9"):
            return true;
    }
    return false;
}

static bool IsCRTLikeSection(const Function& f)
{
    if (!f.hasSection()) return false;
    StringRef s = f.getSection();
    return s.starts_with(".CRT$") || s.starts_with(".tls$");
}

static bool IsThunkLike(const Function& f)
{
    if (f.isDeclaration()) return false;
    unsigned nondbg = 0;
    bool hascall = false;
    for (const BasicBlock& bb : f)
    {
        for (const Instruction& i : bb)
        {
            if (isa<DbgInfoIntrinsic>(&i)) continue;
            ++nondbg;
            if (nondbg > 3) return false;
            if (auto* cb = dyn_cast<CallBase>(&i))
            {
                if (!cb->getIntrinsicID()) hascall = true;
            }
        }
    }
    return hascall;
}

struct XRefInfo
{
    DenseMap<const Function*, unsigned> CallCount;
    DenseSet<const Function*> AddressTaken;
};

static XRefInfo BuildXRefs(const Module& m)
{
    XRefInfo info;
    for (const Function& f : m)
    {
        for (const User* u : f.users())
        {
            if (const auto* cb = dyn_cast<CallBase>(u))
            {
                if (cb->getCalledFunction() == &f)
                {
                    ++info.CallCount[&f];
                    continue;
                }
            }
            info.AddressTaken.insert(&f);
        }
    }
    return info;
}

static bool HasFuncletPads(const Function& f)
{
    for (const BasicBlock& bb : f)
    {
        if (bb.isEHPad()) return true;
        for (const Instruction& i : bb)
            if (isa<FuncletPadInst>(&i) || isa<CatchSwitchInst>(&i)) return true;
    }
    return false;
}

static bool HasMustTailCall(const Function& f)
{
    for (const BasicBlock& bb : f)
        for (const Instruction& i : bb)
            if (auto* cb = dyn_cast<CallBase>(&i))
                if (cb->isMustTailCall()) return true;
    return false;
}

static bool IsTinyFn(const Function& f)
{
    unsigned n = 0;
    for (const BasicBlock& bb : f)
        for (const Instruction& i : bb)
        {
            if (isa<DbgInfoIntrinsic>(&i)) continue;
            if (++n > 8) return false;
        }
    return true;
}

static bool EligibleFn(Function& f, const XRefInfo& xr)
{
    if (f.isDeclaration()) return false;
    if (IsCRTLikeName(f.getName())) return false;
    if (IsCRTLikeSection(f)) return false;
    if (HasAnnotation(f, "norop")) return false;
    if (HasAnnotation(f, "noobfus")) return false;
    if (f.hasFnAttribute(Attribute::AlwaysInline)) return false;
    if (f.hasFnAttribute(Attribute::Naked)) return false;
    if (HasFuncletPads(f)) return false;
    if (HasMustTailCall(f)) return false;
    if (IsThunkLike(f)) return false;
    if (IsTinyFn(f)) return false;
    auto it = xr.CallCount.find(&f);
    unsigned c = (it == xr.CallCount.end()) ? 0u : it->second;
    if (c >= XrefThresh) return false;
    if (xr.AddressTaken.count(&f)) return false;
    return true;
}

bool RunGadgets(Module& m)
{
    {
        const auto discovered = DiscoverImportedDLLs(m);
        for (const std::string& nm : discovered) HarvestDll(nm);
    }

    if (DllModules.empty() || JmpPool.empty()) return false;

    ModuleNameHash = HashModuleUtf16Upper(m.getName().str());
    SiteCounter = 0;
    SlotFillDone.clear();
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)ModuleNameHash);
        NameSuffix = buf;
    }

    const XRefInfo xr = BuildXRefs(m);
    bool mutated = false;

    std::vector<Function*> funcs;
    funcs.reserve(m.size());
    for (Function& f : m) funcs.push_back(&f);
    std::stable_sort(funcs.begin(), funcs.end(), [](Function* a, Function* b)
    {
        return std::hash<std::string>{}(a->getName().str()) < std::hash<std::string>{}(b->getName().str());
    });

    unsigned memmodremaining = MemModBudget;

    for (Function* fp : funcs)
    {
        Function& f = *fp;
        if (!EligibleFn(f, xr)) continue;

        DominatorTree dt;
        LoopInfo li;
        if (!f.isDeclaration())
        {
            dt.recalculate(f);
            li.analyze(dt);
        }

        struct MemPick
        {
            enum { KLoad, KStore } Kind;
            Instruction* I;
            unsigned Prio;
        };
        std::vector<Instruction*> picksa;
        std::vector<MemPick> picksmem;

        auto scoremem = [](Instruction* i, bool isload) -> unsigned
        {
            Type* t = isload ? cast<LoadInst>(i)->getType() : cast<StoreInst>(i)->getValueOperand()->getType();
            if (t->isPointerTy()) return 2;
            if (t->isIntegerTy(64)) return 2;
            return 1;
        };

        for (Instruction& i : instructions(f))
        {
            if (!f.isDeclaration() && li.getLoopFor(i.getParent())) continue;
            if (i.getMetadata("lic.rop")) continue;
            if (i.getMetadata("lic.p2.disk")) continue;

            if (auto* cb = dyn_cast<CallBase>(&i))
            {
                Value* callee = cb->getCalledOperand();
                if (auto* i2p = dyn_cast_or_null<IntToPtrInst>(callee))
                    if (i2p->getMetadata("lic.phase1")) picksa.push_back(&i);
                continue;
            }
            if (auto* liptr = dyn_cast<LoadInst>(&i))
            {
                picksmem.push_back({MemPick::KLoad, liptr, scoremem(liptr, true)});
            }
            else if (auto* siptr = dyn_cast<StoreInst>(&i))
            {
                picksmem.push_back({MemPick::KStore, siptr, scoremem(siptr, false)});
            }
        }

        if (!picksmem.empty())
        {
            std::mt19937 rng((unsigned)(SeedSalt ^ std::hash<std::string>{}(f.getName().str())));
            std::shuffle(picksmem.begin(), picksmem.end(), rng);
            std::stable_sort(picksmem.begin(), picksmem.end(), [](const MemPick& a, const MemPick& b)
            {
                return a.Prio > b.Prio;
            });

            if (picksmem.size() > MaxMemPerFn) picksmem.resize(MaxMemPerFn);
            if (picksmem.size() > memmodremaining) picksmem.resize(memmodremaining);
        }

        unsigned fnremaining = MaxPerFn;

        if (picksa.size() > fnremaining)
        {
            std::mt19937 rng((unsigned)(SeedSalt ^ std::hash<std::string>{}(f.getName().str()) ^ 0xA1A1A1A1u));
            std::shuffle(picksa.begin(), picksa.end(), rng);
            picksa.resize(fnremaining);
        }
        for (Instruction* i : picksa)
        {
            if (TryEmitCallSite(cast<CallBase>(i)))
            {
                if (fnremaining > 0) --fnremaining;
                mutated = true;
            }
        }

        if (picksmem.size() > fnremaining) picksmem.resize(fnremaining);
        for (const MemPick& p : picksmem)
        {
            bool ok = (p.Kind == MemPick::KLoad) ? TryEmitLoadSite(cast<LoadInst>(p.I)) : TryEmitStoreSite(cast<StoreInst>(p.I));
            if (ok)
            {
                if (memmodremaining > 0) --memmodremaining;
                mutated = true;
            }
        }
    }

    return mutated;
}