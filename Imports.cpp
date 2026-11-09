#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "Imports.h"

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
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace llvm;

static constexpr const char* SystemDir = "C:\\Windows\\System32";
static constexpr int MaxFwdHops = 16;

const char* const SeedHostPool[] =
{
    "ntdll.dll", "kernelbase.dll", "win32u.dll", "gdi32full.dll",
    "combase.dll", "sechost.dll", "shcore.dll", "bcrypt.dll", "ucrtbase.dll",
    "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll",
    "shell32.dll", "shlwapi.dll", "ole32.dll", "oleaut32.dll",
    "ws2_32.dll", "winhttp.dll", "wininet.dll", "msvcrt.dll",
    "crypt32.dll", "psapi.dll", "version.dll", "setupapi.dll",
    "comctl32.dll", "comdlg32.dll", "wintrust.dll", "dbghelp.dll",
    "dxgi.dll", "d3d11.dll", "d3d12.dll",
};
const unsigned SeedHostPoolSize = sizeof(SeedHostPool) / sizeof(SeedHostPool[0]);

static std::string ToLowerASCII(std::string s)
{
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return s;
}

static bool IsAPISet(const std::string& n)
{
    return n.rfind("api-ms-", 0) == 0 || n.rfind("ext-ms-", 0) == 0;
}

static bool IsStubForwarderBytes(const uint8_t* p, size_t n)
{
    size_t i = 0;
    for (;;)
    {
        if (i + 4 <= n && p[i] == 0xF3 && p[i+1] == 0x0F && p[i+2] == 0x1E && p[i+3] == 0xFA) { i += 4; continue; }
        if (i + 1 <= n && p[i] == 0x90) { i += 1; continue; }
        if (i + 2 <= n && p[i] == 0x66 && p[i+1] == 0x90) { i += 2; continue; }
        if (i + 3 <= n && p[i] == 0x0F && p[i+1] == 0x1F && p[i+2] == 0x00) { i += 3; continue; }
        if (i + 4 <= n && p[i] == 0x0F && p[i+1] == 0x1F && p[i+2] == 0x40 && p[i+3] == 0x00) { i += 4; continue; }
        if (i + 5 <= n && p[i] == 0x0F && p[i+1] == 0x1F && p[i+2] == 0x44 && p[i+3] == 0x00 && p[i+4] == 0x00) { i += 5; continue; }
        if (i + 6 <= n && p[i] == 0x66 && p[i+1] == 0x0F && p[i+2] == 0x1F && p[i+3] == 0x44 && p[i+4] == 0x00 && p[i+5] == 0x00) { i += 6; continue; }
        break;
    }
    if (i >= n) return false;
    const uint8_t* q = p + i;
    const size_t m = n - i;
    if (m >= 6 && q[0] == 0xFF && q[1] == 0x25) return true;
    if (m >= 7 && q[0] == 0x48 && q[1] == 0xFF && q[2] == 0x25) return true;
    if (m >= 5 && q[0] == 0xE9) return true;
    if (m >= 10 && q[0] == 0x48 && q[1] == 0x8B && q[2] == 0x05 && q[7] == 0x48 && q[8] == 0xFF && q[9] == 0xE0) return true;
    if (m >= 9  && q[0] == 0x48 && q[1] == 0x8B && q[2] == 0x05 && q[7] == 0xFF && q[8] == 0xE0) return true;
    return false;
}

#ifdef _WIN32
static bool ReadCodeBytes(const std::wstring& dllpath, uint32_t coderva, uint8_t* out, size_t outsize)
{
    HANDLE file = CreateFileW(dllpath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER fs{};
    if (!GetFileSizeEx(file, &fs) || fs.QuadPart < 0x1000)
    {
        CloseHandle(file);
        return false;
    }
    HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping) { CloseHandle(file); return false; }
    auto* base = (const uint8_t*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(mapping); CloseHandle(file); return false; }
    auto cleanup = [&]()
    {
        UnmapViewOfFile(base);
        CloseHandle(mapping);
        CloseHandle(file);
    };
    const uint64_t fsize = (uint64_t)fs.QuadPart;
    auto* dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || (uint64_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fsize)
    {
        cleanup();
        return false;
    }
    auto* nt = (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        cleanup();
        return false;
    }
    const uint16_t seccount = nt->FileHeader.NumberOfSections;
    const uint64_t sectbloff = (uint64_t)dos->e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    if (sectbloff + (uint64_t)seccount * sizeof(IMAGE_SECTION_HEADER) > fsize)
    {
        cleanup();
        return false;
    }
    auto* sections = (const IMAGE_SECTION_HEADER*)(base + sectbloff);
    uint64_t off = 0;
    for (uint16_t i = 0; i < seccount; ++i)
    {
        const uint32_t span = (std::max)(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
        if (coderva >= sections[i].VirtualAddress && coderva - sections[i].VirtualAddress < span)
        {
            off = (uint64_t)sections[i].PointerToRawData + (coderva - sections[i].VirtualAddress);
            break;
        }
    }
    if (!off || off + outsize > fsize) { cleanup(); return false; }
    std::memcpy(out, base + off, outsize);
    cleanup();
    return true;
}
#endif

static std::unordered_map<std::string, GlobalVariable*> HostNameGVCache;

std::string UnmangleCName(StringRef n)
{
    std::string s = n.str();
    if (!s.empty() && s[0] == '_') s.erase(0, 1);
    const size_t at = s.find('@');
    if (at != std::string::npos) s.resize(at);
    return s;
}

bool IsEligibleDLLImport(const Function& f)
{
    if (!f.isDeclaration()) return false;
    if (f.isIntrinsic()) return false;
    if (!f.hasDLLImportStorageClass()) return false;
    if (f.getLinkage() != GlobalValue::ExternalLinkage) return false;
    return true;
}

bool IsRealCodeExport(const std::wstring& dllpath, uint32_t rva)
{
#ifdef _WIN32
    uint8_t bytes[32] = {};
    if (!ReadCodeBytes(dllpath, rva, bytes, sizeof(bytes))) return false;
    return !IsStubForwarderBytes(bytes, sizeof(bytes));
#else
    (void)dllpath;
    (void)rva;
    return true;
#endif
}

bool SourceHost(const std::string& hostlower, HostState& out)
{
    out.DLLLower = hostlower;
    out.Sourced = false;
    if (IsAPISet(hostlower)) return false;

    std::filesystem::path syspath(SystemDir);
    syspath /= hostlower;

    DLLGrabberUtility::DllIdentity id;
    std::wstring err;
    if (!DLLGrabberUtility::Instance().GrabIdentity(syspath.wstring(), id, err))
    {
        return false;
    }

    OfficialDllDownloader::DownloadResult dr;
    if (OfficialDllDownloader::Instance().TryGetCachedDll(id.DllName, id.TimeDateStamp, id.SizeOfImage, dr) && dr.Success)
    {
        out.CanonicalPath = dr.OutputPath;
    }
    else if (OfficialDllDownloader::Instance().DownloadDll(id.DllName, id.TimeDateStamp, id.SizeOfImage, dr) && dr.Success)
    {
        out.CanonicalPath = dr.OutputPath;
    }
    else
    {
        return false;
    }

    if (!DLLExportGrabber::Instance().GrabExports(out.CanonicalPath, out.Exports, err))
    {
        return false;
    }
    out.Sourced = true;
    return true;
}

bool ResolveImport(const std::string& firsthost, const std::string& firstname, std::map<std::string, HostState>& hosts, std::string& outhost, uint32_t& outrva, std::string& outreason)
{
    std::string host = firsthost;
    std::string name = firstname;

    for (int hop = 0; hop <= MaxFwdHops; ++hop)
    {
        if (IsAPISet(host))
        {
            outreason = "api-set terminal (" + host + ")";
            return false;
        }
        auto it = hosts.find(host);
        if (it == hosts.end())
        {
            HostState hs;
            SourceHost(host, hs);
            auto ins = hosts.emplace(host, std::move(hs));
            it = ins.first;
        }
        if (!it->second.Sourced)
        {
            outreason = "host not sourced (" + host + ")";
            return false;
        }
        const DLLExportGrabber::ExportTable& t = it->second.Exports;
        auto ni = t.NameToIndex.find(name);
        if (ni == t.NameToIndex.end())
        {
            outreason = name + " not exported by " + host;
            return false;
        }
        const DLLExportGrabber::ExportEntry& e = t.Entries[ni->second];
        if (!e.Forwarded)
        {
            outhost = host;
            outrva = e.Rva;
            return true;
        }
        if (e.ForwardApiset)
        {
            outreason = "forwards to api-set " + e.ForwardDll;
            return false;
        }
        if (e.ForwardByOrdinal)
        {
            outreason = "forwards by ordinal to " + e.ForwardDll;
            return false;
        }
        if (e.ForwardDll.empty() || e.ForwardName.empty())
        {
            outreason = "malformed forwarder from " + host;
            return false;
        }
        host = e.ForwardDll;
        name = e.ForwardName;
    }
    outreason = "forwarder chain exceeded " + std::to_string(MaxFwdHops) + " hops";
    return false;
}

GlobalVariable* GetOrCreateHostNameGV(Module& m, const std::string& host)
{
    auto it = HostNameGVCache.find(host);
    if (it != HostNameGVCache.end()) return it->second;
    LLVMContext& c = m.getContext();
    Constant* name = ConstantDataArray::getString(c, host, true);
    auto* gv = new GlobalVariable(m, name->getType(), true, GlobalValue::PrivateLinkage, name, "__lic_host_name");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    HostNameGVCache[host] = gv;
    return gv;
}

void ResetHostNameGVCache()
{
    HostNameGVCache.clear();
}

FunctionCallee DeclGetModuleHandleA(Module& m)
{
    LLVMContext& c = m.getContext();
    Type* ptrty = PointerType::get(c, 0);
    FunctionType* ft = FunctionType::get(ptrty, {ptrty}, false);
    FunctionCallee cal = m.getOrInsertFunction("GetModuleHandleA", ft);
    if (auto* f = dyn_cast<Function>(cal.getCallee()))
    {
        f->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
        f->setLinkage(GlobalValue::ExternalLinkage);
    }
    return cal;
}

FunctionCallee DeclImport(Module& m, StringRef name, FunctionType* ft)
{
    FunctionCallee c = m.getOrInsertFunction(name, ft);
    if (auto* f = dyn_cast<Function>(c.getCallee()))
    {
        f->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
        f->setLinkage(GlobalValue::ExternalLinkage);

        LLVMContext& ctx = m.getContext();
        const std::string pinname = "__lic_pin_" + name.str();
        if (!m.getGlobalVariable(pinname))
        {
            pin the IAT entry via llvm.used GV
            auto* pin = new GlobalVariable(m, PointerType::get(ctx, 0), true, GlobalValue::PrivateLinkage, f, pinname);
            pin->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
            appendToUsed(m, {pin});
        }
    }
    return c;
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

static uint8_t MatchGPULane(StringRef n)
{
    switch (FNV1a64Range(n))
    {
        case FNV1a64("CreateDXGIFactory"):
        case FNV1a64("CreateDXGIFactory1"):
        case FNV1a64("CreateDXGIFactory2"):
        case FNV1a64("DXGIDeclareAdapterRemovalSupport"):
        case FNV1a64("DXGIGetDebugInterface1"):
        case FNV1a64("DXGIDisableVBlankVirtualization"):
            return ImpMaskDXGI;
        case FNV1a64("D3D11CreateDevice"):
        case FNV1a64("D3D11CreateDeviceAndSwapChain"):
        case FNV1a64("D3D11On12CreateDevice"):
            return ImpMaskD3D11;
        case FNV1a64("D3D12CreateDevice"):
        case FNV1a64("D3D12GetDebugInterface"):
        case FNV1a64("D3D12SerializeRootSignature"):
        case FNV1a64("D3D12SerializeVersionedRootSignature"):
        case FNV1a64("D3D12CreateVersionedRootSignatureDeserializer"):
        case FNV1a64("D3D12EnableExperimentalFeatures"):
            return ImpMaskD3D12;
        case FNV1a64("EnumDisplayDevicesW"):
        case FNV1a64("EnumDisplayDevicesA"):
        case FNV1a64("EnumDisplaySettingsW"):
        case FNV1a64("EnumDisplaySettingsA"):
        case FNV1a64("EnumDisplaySettingsExW"):
        case FNV1a64("EnumDisplaySettingsExA"):
            return ImpMaskDisplay;
    }
    return 0;
}

uint8_t DiscoverGPUImportMask(Module& m)
{
    uint8_t mask = 0;
#ifdef _WIN32
    for (Function& f : m)
    {
        if (!f.isDeclaration()) continue;
        if (f.isIntrinsic()) continue;
        const std::string cname = UnmangleCName(f.getName());
        mask |= MatchGPULane(cname);
    }

    std::map<std::string, HostState> hosts;
    for (Function& f : m)
    {
        if (!IsEligibleDLLImport(f)) continue;
        const std::string cname = UnmangleCName(f.getName());
        for (unsigned s = 0; s < SeedHostPoolSize; ++s)
        {
            const std::string hostlower = SeedHostPool[s];
            auto it = hosts.find(hostlower);
            if (it == hosts.end())
            {
                HostState hs;
                SourceHost(hostlower, hs);
                it = hosts.emplace(hostlower, std::move(hs)).first;
            }
            if (!it->second.Sourced) continue;
            if (!it->second.Exports.NameToIndex.count(cname)) continue;
            std::string termhost;
            uint32_t termrva = 0;
            std::string reason;
            if (!ResolveImport(hostlower, cname, hosts, termhost, termrva, reason)) break;
            if      (termhost == "dxgi.dll")   mask |= ImpMaskDXGI;
            else if (termhost == "d3d11.dll")  mask |= ImpMaskD3D11;
            else if (termhost == "d3d12.dll")  mask |= ImpMaskD3D12;
            else if (termhost == "gdi32.dll")  mask |= ImpMaskGDI;
            else if (termhost == "user32.dll") mask |= ImpMaskUser32;
            break;
        }
    }

    //  display and disk lanes inherit from their host DLLs. EnumDisplayDevicesW/EnumDisplaySettingsExW live in user32, disk uses kernel32 (universal across any PE)
    if (mask & ImpMaskUser32) mask |= ImpMaskDisplay;
    mask |= ImpMaskDisk;
#else
    (void)m;
#endif
    return mask;
}

uint8_t GPUAvailableMask(uint8_t impmask, uint8_t obfmask)
{
    uint8_t out = 0;
    const bool dxgitgt = (impmask & ImpMaskDXGI) != 0;
    const bool d3d11tgt = (impmask & ImpMaskD3D11) != 0;
    const bool d3d12tgt = (impmask & ImpMaskD3D12) != 0;
    const bool gditgt = (impmask & ImpMaskGDI) != 0;
    const bool user32tgt = (impmask & ImpMaskUser32) != 0;
    const bool displaytgt = (impmask & ImpMaskDisplay) != 0;
    const bool disktgt = (impmask & ImpMaskDisk) != 0;
    if (dxgitgt                    && (obfmask & OfMaskDXGI))    out |= ImpMaskDXGI;
    if (d3d11tgt   && dxgitgt      && (obfmask & OfMaskD3D11))   out |= ImpMaskD3D11;
    if (d3d12tgt   && dxgitgt      && (obfmask & OfMaskD3D12))   out |= ImpMaskD3D12;
    if (gditgt     && user32tgt    && (obfmask & OfMaskGDI))     out |= ImpMaskGDI;
    if (user32tgt                  && (obfmask & OfMaskUser32))  out |= ImpMaskUser32;
    if (displaytgt && user32tgt    && (obfmask & OfMaskDisplay)) out |= ImpMaskDisplay;
    if (disktgt                    && (obfmask & OfMaskDisk))    out |= ImpMaskDisk;
    return out;
}

std::vector<std::string> DiscoverImportedDLLs(Module& m)
{
    std::vector<std::string> out;
#ifdef _WIN32
    std::unordered_set<std::string> seen;
    std::map<std::string, HostState> hosts;

    for (Function& f : m)
    {
        if (!IsEligibleDLLImport(f)) continue;
        const std::string cname = UnmangleCName(f.getName());
        for (unsigned s = 0; s < SeedHostPoolSize; ++s)
        {
            const std::string hostlower = SeedHostPool[s];
            auto it = hosts.find(hostlower);
            if (it == hosts.end())
            {
                HostState hs;
                SourceHost(hostlower, hs);
                it = hosts.emplace(hostlower, std::move(hs)).first;
            }
            if (!it->second.Sourced) continue;
            if (!it->second.Exports.NameToIndex.count(cname)) continue;
            std::string termhost;
            uint32_t termrva = 0;
            std::string reason;
            if (ResolveImport(hostlower, cname, hosts, termhost, termrva, reason))
            {
                if (seen.insert(termhost).second) out.push_back(termhost);
                break;
            }
        }
    }
#else
    (void)m;
#endif
    return out;
}

bool RunImports(Module& m)
{
    ResetHostNameGVCache();

    LLVMContext& context = m.getContext();

    std::map<std::string, HostState> hosts;

    struct Resolved
    {
        std::string Host;
        uint32_t RVA;
    };
    std::unordered_map<Function*, Resolved> resolvedmap;

    for (Function& f : m)
    {
        if (!IsEligibleDLLImport(f)) continue;
        const std::string cname = UnmangleCName(f.getName());

        bool ok = false;
        std::string lastreason;
        for (unsigned i = 0; i < SeedHostPoolSize; ++i)
        {
            const std::string host = SeedHostPool[i];
            auto it = hosts.find(host);
            if (it == hosts.end())
            {
                HostState hs;
                SourceHost(host, hs);
                auto ins = hosts.emplace(host, std::move(hs));
                it = ins.first;
            }
            if (!it->second.Sourced) continue;
            if (!it->second.Exports.NameToIndex.count(cname)) continue;

            std::string termhost;
            uint32_t termrva = 0;
            std::string reason;
            if (ResolveImport(host, cname, hosts, termhost, termrva, reason))
            {
                HostState& th = hosts[termhost];
                if (!IsRealCodeExport(th.CanonicalPath, termrva))
                {
                    lastreason = cname + " at " + termhost + " is a stub";
                    continue;
                }
                resolvedmap[&f] = {termhost, termrva};
                ok = true;
                break;
            }
            lastreason = reason;
        }
        (void)ok;
        (void)lastreason;
    }

    if (resolvedmap.empty()) return false;

    struct SiteInfo
    {
        CallBase* Call;
        Function* Callee;
        std::string Host;
        uint32_t RVA;
    };
    std::unordered_map<Function*, std::vector<SiteInfo>> perfnsites;

    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        // bug: skip Phase 1's own helper namespace, but NOT the Phase 2 GPU helpers (__lic_gpu_fp_*) — those contain dllimport calls that MUST get the Phase 1 base+rva rewrite, otherwise their plaintext symbols leak into the final PE import table and defeat the disguise
        if (f.getName().starts_with("__lic_") && !f.getName().starts_with("__lic_gpu_")) continue;
        for (Instruction& i : instructions(f))
        {
            auto* cb = dyn_cast<CallBase>(&i);
            if (!cb) continue;
            if (cb->isInlineAsm()) continue;
            Function* callee = cb->getCalledFunction();
            if (!callee) continue;
            auto rm = resolvedmap.find(callee);
            if (rm == resolvedmap.end()) continue;
            SiteInfo si;
            si.Call = cb;
            si.Callee = callee;
            si.Host = rm->second.Host;
            si.RVA = rm->second.RVA;
            perfnsites[&f].push_back(si);
        }
    }

    if (perfnsites.empty()) return false;

    FunctionCallee getmoda = DeclGetModuleHandleA(m);
    Type* i64 = Type::getInt64Ty(context);
    Type* ptrty = PointerType::get(context, 0);

    unsigned callsrewritten = 0, invokesrewritten = 0;

    for (auto& kv : perfnsites)
    {
        Function* f = kv.first;
        std::vector<SiteInfo>& sitesinf = kv.second;

        std::vector<std::string> orderedhosts;
        std::unordered_map<std::string, uint32_t> hostslot;
        for (const SiteInfo& si : sitesinf)
        {
            if (!hostslot.count(si.Host))
            {
                hostslot[si.Host] = (uint32_t)orderedhosts.size();
                orderedhosts.push_back(si.Host);
            }
        }
        const uint32_t n = (uint32_t)orderedhosts.size();

        BasicBlock& entrybb = f->getEntryBlock();
        Instruction* ipt = &*entrybb.getFirstInsertionPt();
        IRBuilder<> b(ipt);

        MDNode* p1entry = MDNode::get(context, {MDString::get(context, "p1")});
        auto tagentry = [&](Value* v)
        {
            if (auto* i = dyn_cast<Instruction>(v)) i->setMetadata("lic.phase1", p1entry);
        };

        Value* nslots = ConstantInt::get(i64, (uint64_t)n);
        AllocaInst* tbl = b.CreateAlloca(i64, nslots, "LicTbl");
        tbl->setAlignment(Align(8));
        tagentry(tbl);

        for (uint32_t k = 0; k < n; ++k)
        {
            const std::string& host = orderedhosts[k];
            GlobalVariable* hname = GetOrCreateHostNameGV(m, host);
            Value* h = b.CreateCall(getmoda, {hname}, "LicH");
            Value* hi = b.CreatePtrToInt(h, i64, "LicHi");
            Value* slot = b.CreateGEP(i64, tbl, ConstantInt::get(i64, (uint64_t)k), "LicSlot");
            StoreInst* st = b.CreateStore(hi, slot);
            tagentry(h);
            tagentry(hi);
            tagentry(slot);
            tagentry(st);
        }

        MDNode* p1mark = MDNode::get(context, {MDString::get(context, "p1")});
        auto tag = [&](Value* v)
        {
            if (auto* i = dyn_cast<Instruction>(v)) i->setMetadata("lic.phase1", p1mark);
        };
        for (const SiteInfo& si : sitesinf)
        {
            const uint32_t k = hostslot[si.Host];
            IRBuilder<> sb(si.Call);
            Value* slot = sb.CreateGEP(i64, tbl, ConstantInt::get(i64, (uint64_t)k), "LicSlot");
            Value* base = sb.CreateLoad(i64, slot, "LicBase");
            Value* addr = sb.CreateAdd(base, ConstantInt::get(i64, (uint64_t)(uint32_t)si.RVA), "LicAddr");
            Value* fp = sb.CreateIntToPtr(addr, ptrty, "LicFp");
            tag(slot);
            tag(base);
            tag(addr);
            tag(fp);
            si.Call->setCalledOperand(fp);

            if (isa<InvokeInst>(si.Call)) ++invokesrewritten;
            else ++callsrewritten;
        }
    }

    return callsrewritten + invokesrewritten > 0;
}