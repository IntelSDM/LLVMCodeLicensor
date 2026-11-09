#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "LicensingPass.h"

#include "CPUID.h"
#include "DisplayAdapter.h"
#include "Disk.h"
#include "GPUAdapter.h"
#include "Imports.h"
#include "KUserSharedData.h"
#include "LicenseCollection.h"

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/CommandLine.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <map>
#include <random>
#include <string>
#include <vector>

using namespace llvm;

llvm::cl::opt<bool> LicensingEnable("obf-licensing", llvm::cl::init(true),
    llvm::cl::desc("Phase 1 dllimport->base+rva rewrite, Phase 2 constant encryption keyed off CPUID/KUSER/GPU/display/disk/misc-probe fingerprints, Phase 3 ROP gadget indirection on dispatch tails and selected mem sites."));

static constexpr unsigned XrefThresh = 16;
static constexpr bool SkipLoops = true;
static constexpr bool SkipThunks = true;
static constexpr unsigned LeavesPerSite = 2;
static constexpr double HVLeafBias = 0.6;
static constexpr unsigned MaxPerFn = 20;
static constexpr unsigned KUserFieldsPerSite = 2;
static constexpr unsigned MiscProbesPerSite = 1;
static constexpr bool TSCBracket = false;
static constexpr unsigned TSCShift = 20;
static constexpr unsigned WeightDXGI = 15;
static constexpr unsigned WeightD3D11 = 15;
static constexpr unsigned WeightD3D12 = 15;
static constexpr unsigned WeightGDI = 20;
static constexpr unsigned WeightUser32 = 15;
static constexpr unsigned WeightDisplay = 20;
static constexpr unsigned WeightDisk = 15;
static constexpr unsigned WeightCPUID = 50;
static constexpr unsigned GPUMinFnInsns = 20;

static std::mt19937& GetPRNG()
{
    static std::mt19937 g([]()
    {
        std::random_device rd;
        return (unsigned)(rd() ^ (unsigned)std::chrono::high_resolution_clock::now().time_since_epoch().count());
    }());
    return g;
}

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

enum class GPULane : uint8_t { None = 0, CPUID, DXGI, D3D11, D3D12, GDI, User32, Display, Disk };

static uint64_t GPUFpFor(const ObfGPUFp& fp, GPULane l)
{
    switch (l)
    {
        case GPULane::DXGI:    return fp.DXGI;
        case GPULane::D3D11:   return fp.D3D11;
        case GPULane::D3D12:   return fp.D3D12;
        case GPULane::GDI:     return fp.GDI;
        case GPULane::User32:  return fp.User32;
        case GPULane::Display: return fp.Display;
        case GPULane::Disk:    return fp.Disk;
        default:               return 0;
    }
}

static Function* EnsureGPUHelper(Module& m, GPULane l)
{
    switch (l)
    {
        case GPULane::DXGI:    return EnsureHelperDXGI(m);
        case GPULane::D3D11:   return EnsureHelperD3Dx(m, false);
        case GPULane::D3D12:   return EnsureHelperD3Dx(m, true);
        case GPULane::GDI:     return EnsureHelperGDI(m);
        case GPULane::User32:  return EnsureHelperUser32(m);
        case GPULane::Display: return EnsureHelperDisplay(m);
        case GPULane::Disk:    return nullptr;
        default:               return nullptr;
    }
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
        case FNV1a64("_mainCRTStartup"):
        case FNV1a64("WinMainCRTStartup"):
        case FNV1a64("DllMainCRTStartup"):
        case FNV1a64("mainCRTStartup"):
        case FNV1a64("wmainCRTStartup"):
        case FNV1a64("wWinMainCRTStartup"):
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
            if (const auto* cb = dyn_cast<CallBase>(&i))
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

static bool IsRewritableConstOp(Instruction& i, unsigned opidx)
{
    if (isa<PHINode>(i)) return false;
    if (isa<SwitchInst>(i)) return false;
    if (isa<BranchInst>(i)) return false;
    if (isa<IndirectBrInst>(i)) return false;
    if (isa<LandingPadInst>(i)) return false;
    if (isa<FuncletPadInst>(i)) return false;
    if (isa<IntrinsicInst>(&i)) return false;
    if (isa<DbgInfoIntrinsic>(&i)) return false;
    // alloca array-size as a decrypted ARX result would spin __chkstk through billions of pages on wrong HW targets
    if (isa<AllocaInst>(&i)) return false;

    if (auto* call = dyn_cast<CallBase>(&i))
    {
        if (opidx >= call->arg_size()) return false;
        if (call->paramHasAttr(opidx, Attribute::ImmArg)) return false;
        return true;
    }

    if (auto* gep = dyn_cast<GetElementPtrInst>(&i))
    {
        if (opidx == 0) return false;
        auto gti = gep_type_begin(gep);
        auto end = gep_type_end(gep);
        for (unsigned k = 1; k < opidx && gti != end; ++k, ++gti) {}
        if (gti == end) return false;
        if (gti.getStructTypeOrNull() != nullptr) return false;
        return true;
    }
    return true;
}

struct Rewrite
{
    Instruction* User;
    unsigned OpIdx;
    uint64_t OrigBits;
    unsigned Bw;
};

static void Harvest(Function& f, LoopInfo* li, std::vector<Rewrite>& out)
{
    for (Instruction& i : instructions(f))
    {
        if (i.getMetadata("lic.phase1")) continue;
        if (auto* ci = dyn_cast<CallInst>(&i))
        {
            if (ci->isInlineAsm()) continue;
        }
        const bool inloop = (li && li->getLoopFor(i.getParent()) != nullptr);
        for (unsigned k = 0, e = i.getNumOperands(); k < e; ++k)
        {
            if (!IsRewritableConstOp(i, k)) continue;
            auto* ci = dyn_cast<ConstantInt>(i.getOperand(k));
            if (!ci) continue;
            const unsigned bw = ci->getBitWidth();
            if (bw < 8 || bw > 64) continue;
            const uint64_t v = ci->getZExtValue();
            if (v == 0 || v == 1) continue;
            if (SkipLoops && inloop) continue;
            Rewrite r;
            r.User = &i;
            r.OpIdx = k;
            r.OrigBits = v;
            r.Bw = bw;
            out.push_back(r);
        }
    }
}

static bool EligibleFn(Function& f, const XRefInfo& xr)
{
    if (f.isDeclaration()) return false;
    if (f.getName().starts_with("__lic_")) return false;
    if (HasAnnotation(f, "nolicensing") || HasAnnotation(f, "noobfus")) return false;

    // DiskID/GPUAdapter/DisplayAdapter are author authority overrides
    if (HasDiskIDAnnotation(f)) return true;
    if (HasGPUAdapterAnnotation(f)) return true;
    if (HasDisplayAdapterAnnotation(f)) return true;

    
    if (f.hasFnAttribute(Attribute::Naked)) return false;
    if (IsCRTLikeName(f.getName())) return false;
    if (IsCRTLikeSection(f)) return false;
    if (SkipThunks && IsThunkLike(f)) return false;
    auto it = xr.CallCount.find(&f);
    unsigned c = (it == xr.CallCount.end()) ? 0u : it->second;
    if (c >= XrefThresh) return false;
    if (xr.AddressTaken.count(&f)) return false;
    return true;
}

static bool IsGPUNameBlacklisted(StringRef n)
{
    static const char* bad[] =
    {
        "std::", "??$", "?$",
        "_com_", "CoInit", "OleInit", "CoCreate", "CoGetClassObject",
        "??_G", "??_E",
        "??_R", "??_7", "??_8", "??_9", "??_C@",
        "__ehhandler", "__ehcleanup",
        "__ioinit", "__scrt",
    };
    for (const char* p : bad)
        if (n.contains(p)) return true;
    return false;
}

static unsigned FnNonDbgInsns(const Function& f)
{
    unsigned n = 0;
    for (const BasicBlock& bb : f)
        for (const Instruction& i : bb)
        {
            if (isa<DbgInfoIntrinsic>(&i)) continue;
            ++n;
        }
    return n;
}

static bool GPULaneEligibleFn(Function& f)
{
    if (f.getName().starts_with("__lic_")) return false;
    if (f.getName().starts_with("__ropf_")) return false;
    if (HasDiskIDAnnotation(f)) return true;
    if (HasGPUAdapterAnnotation(f)) return true;
    if (HasDisplayAdapterAnnotation(f)) return true;
    if (IsGPUNameBlacklisted(f.getName())) return false;
    if (FnNonDbgInsns(f) < GPUMinFnInsns) return false;
    return true;
}

// when forcemask != 0 the author authority (GPUAdapter/DisplayAdapter) binds the site to a specific lane family; CPUID fallback is excluded on purpose 
static constexpr uint8_t GPUFamilyMask = ImpMaskDXGI | ImpMaskD3D11 | ImpMaskD3D12;
static constexpr uint8_t DisplayFamilyMask = ImpMaskGDI | ImpMaskUser32 | ImpMaskDisplay;

static GPULane PickSiteLane(uint8_t gpuavail, bool fngpueligible, uint8_t forcemask)
{
    struct Opt { GPULane L; unsigned W; };
    SmallVector<Opt, 8> opts;

    if (forcemask != 0)
    {
        const uint8_t avail = gpuavail & forcemask;
        if (avail & ImpMaskDXGI)    opts.push_back({GPULane::DXGI,    WeightDXGI});
        if (avail & ImpMaskD3D11)   opts.push_back({GPULane::D3D11,   WeightD3D11});
        if (avail & ImpMaskD3D12)   opts.push_back({GPULane::D3D12,   WeightD3D12});
        if (avail & ImpMaskGDI)     opts.push_back({GPULane::GDI,     WeightGDI});
        if (avail & ImpMaskUser32)  opts.push_back({GPULane::User32,  WeightUser32});
        if (avail & ImpMaskDisplay) opts.push_back({GPULane::Display, WeightDisplay});
    }
    else
    {
        opts.push_back({GPULane::CPUID, WeightCPUID});
        if (fngpueligible)
        {
            if (gpuavail & ImpMaskDXGI)    opts.push_back({GPULane::DXGI,    WeightDXGI});
            if (gpuavail & ImpMaskD3D11)   opts.push_back({GPULane::D3D11,   WeightD3D11});
            if (gpuavail & ImpMaskD3D12)   opts.push_back({GPULane::D3D12,   WeightD3D12});
            if (gpuavail & ImpMaskGDI)     opts.push_back({GPULane::GDI,     WeightGDI});
            if (gpuavail & ImpMaskUser32)  opts.push_back({GPULane::User32,  WeightUser32});
            if (gpuavail & ImpMaskDisplay) opts.push_back({GPULane::Display, WeightDisplay});
            if (gpuavail & ImpMaskDisk)    opts.push_back({GPULane::Disk,    WeightDisk});
        }
    }
    unsigned total = 0;
    for (const Opt& o : opts) total += o.W;
    if (total == 0 || opts.empty()) return GPULane::None;
    std::uniform_int_distribution<unsigned> d(0, total - 1);
    unsigned r = d(GetPRNG());
    unsigned acc = 0;
    for (const Opt& o : opts)
    {
        acc += o.W;
        if (r < acc) return o.L;
    }
    return opts.front().L;
}

static Value* EmitGPULaneDecrypt(IRBuilder<>& b, Module& m, GPULane lane, uint64_t enc, uint8_t val1, uint8_t val2, uint64_t seedouter, Type* outty)
{
    LLVMContext& c = b.getContext();
    Type* i64 = Type::getInt64Ty(c);
    if (lane == GPULane::Disk) std::abort();
    Function* helper = EnsureGPUHelper(m, lane);
    CallInst* fpcall = b.CreateCall(helper->getFunctionType(), helper, {}, "LicP2Gpu");
    fpcall->setDoesNotThrow();
    Value* k = b.CreateXor(fpcall, ConstantInt::get(i64, seedouter), "LicP2K");
    return EmitARXDecrypt(b, enc, val1, val2, k, outty);
}

bool RunConstEncryption(Module& m)
{
    const CollectedFingerprints& cf = CollectBuildTimeFingerprints();
    const HwFingerprint& obfcpuid = cf.CPUIDAndKUser;

    ObfGPUFp obfgpu = cf.GPU;
    uint8_t gpuavail = GPUAvailableMask(DiscoverGPUImportMask(m), obfgpu.HaveMask);

    const XRefInfo xr = BuildXRefs(m);

    bool mutated = false;

    //  first dibs ordering for author authority tags. DiskID before GPUAdapter before DisplayAdapter before the auto mode functions
    std::vector<Function*> ordered;
    ordered.reserve(m.size());
    for (Function& f : m)
        if (HasDiskIDAnnotation(f)) ordered.push_back(&f);
    for (Function& f : m)
        if (!HasDiskIDAnnotation(f) && HasGPUAdapterAnnotation(f)) ordered.push_back(&f);
    for (Function& f : m)
        if (!HasDiskIDAnnotation(f) && !HasGPUAdapterAnnotation(f) && HasDisplayAdapterAnnotation(f)) ordered.push_back(&f);
    for (Function& f : m)
        if (!HasDiskIDAnnotation(f) && !HasGPUAdapterAnnotation(f) && !HasDisplayAdapterAnnotation(f)) ordered.push_back(&f);

    for (Function* fp : ordered)
    {
        Function& f = *fp;
        if (!EligibleFn(f, xr)) continue;

        DominatorTree dt;
        LoopInfo li;
        if (SkipLoops && !f.isDeclaration())
        {
            dt.recalculate(f);
            li.analyze(dt);
        }

        std::vector<Rewrite> sites;
        Harvest(f, (SkipLoops && !f.isDeclaration()) ? &li : nullptr, sites);
        if (sites.empty()) continue;

        if (sites.size() > MaxPerFn)
        {
            std::shuffle(sites.begin(), sites.end(), GetPRNG());
            sites.resize(MaxPerFn);
        }

        const bool fngpuok = (gpuavail != 0) && GPULaneEligibleFn(f);

        const bool fnhasdiskid = HasDiskIDAnnotation(f);
        const bool fnhasgpuadapter = !fnhasdiskid && HasGPUAdapterAnnotation(f);
        const bool fnhasdisplayadapter = !fnhasdiskid && !fnhasgpuadapter && HasDisplayAdapterAnnotation(f);

        uint8_t gpuavailfn = gpuavail;
        if (!fnhasdiskid) gpuavailfn &= ~ImpMaskDisk;

        uint8_t fnforcemask = 0;
        if (fnhasgpuadapter) fnforcemask = GPUFamilyMask;
        else if (fnhasdisplayadapter) fnforcemask = DisplayFamilyMask;

        for (const Rewrite& r : sites)
        {
            IRBuilder<> b(r.User);

            GPULane lane;
            if (fnhasdiskid)
            {
                lane = GPULane::Disk;
            }
            else if (fnforcemask != 0)
            {
               
                lane = PickSiteLane(gpuavailfn, true, fnforcemask);
            }
            else if (gpuavail != 0)
            {
                lane = PickSiteLane(gpuavailfn, fngpuok, 0);
            }
            else
            {
                lane = GPULane::CPUID;
            }

            if (lane == GPULane::None) continue;

            const uint8_t val1 = RandRot();
            const uint8_t val2 = (uint8_t)(64 - val1);
            const uint64_t seedouter = RandU64();

            if (lane == GPULane::Disk)
            {
                if (obfgpu.DiskPool.empty()) continue;
                std::uniform_int_distribution<size_t> poolpick(0, obfgpu.DiskPool.size() - 1);
                const DiskBucketing& bksite = obfgpu.DiskPool[poolpick(GetPRNG())];

                uint64_t hbase = FNVInit;
                hbase = FNVFoldU32(hbase, (uint32_t)bksite.CandidateIdx);
                hbase = FNVFoldU32(hbase, (uint32_t)DiskCenterBucket);
                const uint64_t gpufp = SentinelSafe(hbase);
                const uint64_t kobf = gpufp ^ seedouter;
                const uint64_t enc = ARXEncrypt(r.OrigBits, kobf, val1, val2);

                Value* kdisk = EmitDiskInlineKey(b, m, bksite);
                Value* ksite = b.CreateXor(kdisk, ConstantInt::get(Type::getInt64Ty(b.getContext()), seedouter), "LicP2K");
                Value* dec = EmitARXDecrypt(b, enc, val1, val2, ksite, r.User->getOperand(r.OpIdx)->getType());

                r.User->setOperand(r.OpIdx, dec);

              
                {
                    MDNode* disktag = MDNode::get(m.getContext(), {});
                    BasicBlock* contbb = r.User->getParent();
                    for (Instruction& i : *contbb)
                    {
                        if (&i == r.User) break;
                        i.setMetadata("lic.p2.disk", disktag);
                    }
                }

                mutated = true;
                continue;
            }

            if (lane != GPULane::CPUID)
            {
                const uint64_t gpufp = GPUFpFor(obfgpu, lane);
                const uint64_t kobf = gpufp ^ seedouter;
                const uint64_t enc = ARXEncrypt(r.OrigBits, kobf, val1, val2);

                Value* dec = EmitGPULaneDecrypt(b, m, lane, enc, val1, val2, seedouter, r.User->getOperand(r.OpIdx)->getType());
                r.User->setOperand(r.OpIdx, dec);
                mutated = true;
                continue;
            }

            const std::vector<unsigned> leaves = PickLeaves(LeavesPerSite, HVLeafBias);
            const std::vector<unsigned> kuser = PickKUserFields(KUserFieldsPerSite);
            const std::vector<unsigned> misc = PickMiscProbes(MiscProbesPerSite);

            const uint8_t rothi = RandRot();
            const uint8_t rotlo = RandRot();
            const uint64_t seedstash = RandU64();

            const uint64_t kcpuclean = FoldFingerprint(obfcpuid, leaves, kuser, misc, rothi, rotlo) ^ seedstash;
            const uint64_t kobf = kcpuclean ^ seedouter;
            const uint64_t enc = ARXEncrypt(r.OrigBits, kobf, val1, val2);

            Value* kcpu = EmitCPUIDFoldKey(b, leaves, kuser, misc, TSCBracket, TSCShift, rothi, rotlo, seedstash);
            Value* ksite = b.CreateXor(kcpu, ConstantInt::get(Type::getInt64Ty(b.getContext()), seedouter), "LicP2K");
            Value* dec = EmitARXDecrypt(b, enc, val1, val2, ksite, r.User->getOperand(r.OpIdx)->getType());

            r.User->setOperand(r.OpIdx, dec);
            mutated = true;
        }
    }

    return mutated;
}

bool RunLicensing(Module& m)
{
    if (!LicensingEnable) return false;
    bool mutated = false;
    
    mutated |= RunConstEncryption(m);
    mutated |= RunImports(m);
    mutated |= RunGadgets(m);
    return mutated;
}

PreservedAnalyses LicensingPass::run(Module& m, ModuleAnalysisManager&)
{
    bool mutated = RunLicensing(m);
    return mutated ? PreservedAnalyses::none() : PreservedAnalyses::all();
}