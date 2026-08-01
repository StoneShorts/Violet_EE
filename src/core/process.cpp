#include "core/process.hpp"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <fstream>

namespace violet::process
{
namespace
{
    std::wstring to_lower(std::wstring_view s)
    {
        std::wstring out{ s };
        std::transform(out.begin(), out.end(), out.begin(),
                       [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
        return out;
    }

    bool contains(std::wstring_view haystack_lower, std::wstring_view needle_lower)
    {
        return haystack_lower.find(needle_lower) != std::wstring_view::npos;
    }
}

// ---------------------------------------------------------------------------
// Section
// ---------------------------------------------------------------------------

bool Section::executable() const { return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0; }
bool Section::writable()   const { return (characteristics & IMAGE_SCN_MEM_WRITE)   != 0; }

std::string Section::flags_string() const
{
    std::string s;
    s += (characteristics & IMAGE_SCN_MEM_READ)    ? 'R' : '-';
    s += (characteristics & IMAGE_SCN_MEM_WRITE)   ? 'W' : '-';
    s += (characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-';
    return s;
}

const Section* ModuleInfo::find_section(std::string_view n) const
{
    for (const auto& s : sections)
        if (s.name == n)
            return &s;
    return nullptr;
}

std::vector<const Section*> ModuleInfo::executable_sections() const
{
    std::vector<const Section*> out;
    for (const auto& s : sections)
        if (s.executable() && s.size > 0)
            out.push_back(&s);
    return out;
}

std::size_t ModuleInfo::total_executable_bytes() const
{
    std::size_t n = 0;
    for (const auto* s : executable_sections())
        n += s->size;
    return n;
}

std::string ModuleInfo::mitigations_string() const
{
    std::string s;
    const auto add = [&](std::uint16_t bit, const char* name)
    {
        if ((dll_characteristics & bit) != 0)
        {
            if (!s.empty()) s += ' ';
            s += name;
        }
    };

    add(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,    "ASLR");
    add(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "HIGH-ENTROPY");
    add(IMAGE_DLLCHARACTERISTICS_NX_COMPAT,       "DEP");
    add(IMAGE_DLLCHARACTERISTICS_GUARD_CF,        "CFG");
    add(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "FORCE-INTEGRITY");

    return s.empty() ? "(none)" : s;
}

// ---------------------------------------------------------------------------
// inspect - walk the PE headers of a mapped module
// ---------------------------------------------------------------------------

std::optional<ModuleInfo> inspect(void* module_handle)
{
    const auto handle = module_handle ? static_cast<HMODULE>(module_handle)
                                      : GetModuleHandleW(nullptr);
    if (handle == nullptr)
        return std::nullopt;

    // An HMODULE on Windows is, by a happy historical accident, simply the base
    // address the module was mapped at. So we can cast it to a byte pointer and
    // start reading headers directly.
    const auto base = reinterpret_cast<const std::uint8_t*>(handle);

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)      // 'MZ'
        return std::nullopt;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)      // 'PE\0\0'
        return std::nullopt;

    // Guard against accidentally pointing this at a 32-bit module: the 64-bit
    // OptionalHeader layout differs, and we would silently read garbage.
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return std::nullopt;

    ModuleInfo info;
    info.base                = reinterpret_cast<std::uintptr_t>(base);
    info.size                = nt->OptionalHeader.SizeOfImage;
    info.dll_characteristics = nt->OptionalHeader.DllCharacteristics;

    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(handle, path, MAX_PATH);
    info.path = path;

    if (const wchar_t* slash = std::wcsrchr(path, L'\\'))
        info.name = slash + 1;
    else
        info.name = path;

    // NOT nt->OptionalHeader.ImageBase - the loader overwrote that with the
    // runtime base when it relocated us. See the header for the full story.
    if (const auto on_disk = preferred_base_on_disk(info.path))
        info.preferred_base = *on_disk;
    else
        info.preferred_base = info.base;   // degrade to a zero slide rather than lying

    // IMAGE_FIRST_SECTION does the pointer arithmetic to skip past the
    // OptionalHeader (whose size is variable) and land on the section table.
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        Section s;

        // Section names are 8 bytes and are NOT guaranteed to be null
        // terminated when all 8 are used - hence the explicit bounded copy
        // rather than treating it as a C string.
        s.name.assign(reinterpret_cast<const char*>(sec->Name),
                      strnlen(reinterpret_cast<const char*>(sec->Name), 8));

        // VirtualAddress is an RVA, so add the base to get a real address.
        s.start           = info.base + sec->VirtualAddress;
        s.size            = sec->Misc.VirtualSize;
        s.characteristics = sec->Characteristics;

        info.sections.push_back(std::move(s));
    }

    return info;
}

// ---------------------------------------------------------------------------
// preferred_base_on_disk - the same headers, read from the file instead
// ---------------------------------------------------------------------------

std::optional<std::uintptr_t> preferred_base_on_disk(const std::wstring& path)
{
    std::ifstream f{ path, std::ios::binary };
    if (!f)
        return std::nullopt;

    IMAGE_DOS_HEADER dos{};
    f.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!f || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return std::nullopt;

    // On disk the headers are laid out contiguously, so e_lfanew is a plain
    // file offset. (Once mapped it happens to double as an RVA, because the
    // headers always sit at the very start of the image.)
    f.seekg(dos.e_lfanew, std::ios::beg);

    IMAGE_NT_HEADERS64 nt{};
    f.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (!f || nt.Signature != IMAGE_NT_SIGNATURE)
        return std::nullopt;

    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return std::nullopt;

    return static_cast<std::uintptr_t>(nt.OptionalHeader.ImageBase);
}

// ---------------------------------------------------------------------------
// loaded_modules
// ---------------------------------------------------------------------------

std::vector<LoadedModule> loaded_modules()
{
    std::vector<LoadedModule> out;

    // Same Toolhelp API the injector used to find processes, but asking for
    // modules within our own process (th32ProcessID of 0 means "me").
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return out;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Module32FirstW(snap, &entry))
    {
        do
        {
            LoadedModule m;
            m.name = entry.szModule;
            m.base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
            m.size = entry.modBaseSize;
            out.push_back(std::move(m));
        }
        while (Module32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return out;
}

// ---------------------------------------------------------------------------
// classify
// ---------------------------------------------------------------------------

ModuleFlag classify(std::wstring_view module_name)
{
    const std::wstring n = to_lower(module_name);

    // Short, generic tokens must be matched as WHOLE FILENAMES, never as
    // substrings. Learned the hard way: "eac" as a substring happily matches
    // Ol-eac-c.dll, a completely innocent Windows accessibility library, and
    // reports the user's machine as running anti-cheat.
    for (const auto* s : { L"eac.dll", L"eac_launcher.dll", L"vgk.sys" })
        if (n == s)
            return ModuleFlag::AntiCheat;

    // Long, distinctive tokens are safe as substrings. For single-player
    // modding with BattlEye disabled, none of these should be present. If one
    // is, stop and fix the launch options rather than pressing on.
    for (const auto* s : { L"beclient", L"battleye", L"easyanticheat", L"vanguard" })
        if (contains(n, s))
            return ModuleFlag::AntiCheat;

    // Anything that has already hooked the swapchain's Present. These are the
    // real stage 3 hazard: two hooks on one function, installed in an
    // unpredictable order, is a classic source of "works on my machine" crashes
    // and of overlays that render on top of each other.
    for (const auto* s : { L"rtsshooks",      // RivaTuner / MSI Afterburner
                           L"gameoverlay",    // Steam
                           L"discordhook",    // Discord
                           L"nvspcap",        // NVIDIA ShadowPlay / GeForce Experience
                           L"nvcamera",
                           L"fraps",
                           L"obs-",
                           L"openvr",
                           L"overlay" })
        if (contains(n, s))
            return ModuleFlag::PresentHooker;

    for (const auto* s : { L"d3d1", L"dxgi", L"nvngx", L"amd_", L"amdxc", L"vulkan", L"nvapi" })
        if (contains(n, s))
            return ModuleFlag::Graphics;

    return ModuleFlag::Normal;
}

const char* to_string(ModuleFlag f)
{
    switch (f)
    {
        case ModuleFlag::AntiCheat:     return "ANTI-CHEAT";
        case ModuleFlag::PresentHooker: return "PRESENT-HOOK";
        case ModuleFlag::Graphics:      return "graphics";
        default:                        return "";
    }
}
}
