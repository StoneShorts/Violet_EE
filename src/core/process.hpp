#pragma once
//
// Violet - inspecting the process we are living inside
//
// This file is where the reverse-engineering half of the project actually
// begins, even though it looks like plumbing. Everything in stage 5 - the
// pattern scanner, the native table hunt - needs two numbers first:
//
//     "where does the game's CODE start, and how many bytes of it are there?"
//
// Those numbers come from the PE headers, and this is the code that reads them.
//
// ---------------------------------------------------------------------------
// A 60-second tour of the PE format
// ---------------------------------------------------------------------------
//
// Every Windows .exe and .dll is a "PE" (Portable Executable) file. When
// Windows loads one, it maps it into memory almost exactly as it appears on
// disk, so we can read its own headers straight out of RAM:
//
//   offset 0    IMAGE_DOS_HEADER
//               A fossil from 1985. Starts with the bytes "MZ". Its only
//               remaining purpose is the e_lfanew field at offset 0x3C, which
//               says "the real header is this many bytes further in".
//
//   e_lfanew    IMAGE_NT_HEADERS64
//               Starts with "PE\0\0". Contains:
//                 FileHeader.Machine        - 0x8664 means x64
//                 FileHeader.NumberOfSections
//                 OptionalHeader.ImageBase  - the address the linker WANTED
//                 OptionalHeader.SizeOfImage- total bytes once mapped
//
//   after that  IMAGE_SECTION_HEADER[NumberOfSections]
//               The file chopped into labelled regions:
//                 .text   executable code      <-- we scan this
//                 .rdata  constants, vtables
//                 .data   mutable globals
//                 .pdata  exception unwind info
//               Anti-tamper products add their own oddly-named sections, so
//               this list is also a quick way to spot protection.
//
// The gap between ImageBase (what the linker wanted) and the address Windows
// actually loaded us at is called the *relocation slide*. It is the single
// conversion factor between an address in IDA and an address at runtime.
//
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace violet::process
{
    struct Section
    {
        std::string    name;             // ".text", ".rdata", ...
        std::uintptr_t start = 0;        // absolute runtime address
        std::size_t    size  = 0;
        std::uint32_t  characteristics = 0;

        bool executable() const;
        bool writable()   const;
        std::string flags_string() const;   // e.g. "R-X"
    };

    struct ModuleInfo
    {
        std::wstring   name;
        std::wstring   path;
        std::uintptr_t base           = 0;   // where Windows actually put it
        std::uintptr_t preferred_base = 0;   // where the linker wanted it (IDA's view)
        std::size_t    size           = 0;   // SizeOfImage
        std::vector<Section> sections;

        // ida_address + slide() == runtime_address
        std::intptr_t slide() const
        {
            return static_cast<std::intptr_t>(base) - static_cast<std::intptr_t>(preferred_base);
        }

        // Returns the FIRST section with this name.
        //
        // Careful: section names are not unique. GTA5_Enhanced.exe ships with
        // two separate sections both called ".text", so for anything that needs
        // to cover all the code, use executable_sections() instead of this.
        const Section* find_section(std::string_view n) const;

        // Every section marked executable, in image order. This - not ".text" -
        // is what the stage 5 pattern scanner must sweep.
        std::vector<const Section*> executable_sections() const;
        std::size_t total_executable_bytes() const;

        // From OptionalHeader.DllCharacteristics. Tells us which of Windows'
        // exploit mitigations the binary opted into, several of which directly
        // affect how we are allowed to hook it.
        std::uint16_t dll_characteristics = 0;
        std::string   mitigations_string() const;
    };

    // Read the PE headers of a module already mapped into our address space.
    // Pass nullptr to inspect the host .exe itself.
    std::optional<ModuleInfo> inspect(void* module_handle);

    // Read OptionalHeader.ImageBase from the file ON DISK.
    //
    // This has to come from disk, and the reason is a genuinely surprising
    // piece of Windows behaviour: when the loader relocates a module, it
    // *rewrites* the ImageBase field inside the mapped copy to the address it
    // actually chose. So reading ImageBase out of memory can only ever tell you
    // where you already are - it always yields a relocation slide of zero.
    //
    // The value IDA shows you is the one still sitting in the file. That is the
    // one we need, so we go and read the file.
    std::optional<std::uintptr_t> preferred_base_on_disk(const std::wstring& path);

    struct LoadedModule
    {
        std::wstring   name;
        std::uintptr_t base = 0;
        std::size_t    size = 0;
    };

    std::vector<LoadedModule> loaded_modules();

    // What a given loaded module means for us. Mostly we care about the two
    // categories that will bite later: anti-cheat, and anything that has
    // already hooked Present (our stage 3 territory).
    enum class ModuleFlag
    {
        Normal,
        AntiCheat,      // BattlEye et al - must not be present for SP modding
        PresentHooker,  // overlays that hook the swapchain; will fight our hook
        Graphics        // d3d12/dxgi/vendor libs - useful context, harmless
    };

    ModuleFlag classify(std::wstring_view module_name);
    const char* to_string(ModuleFlag f);
}
