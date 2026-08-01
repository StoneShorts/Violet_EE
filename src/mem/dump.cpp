#include "mem/dump.hpp"

#include "core/log.hpp"
#include "core/process.hpp"

#include <Windows.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <vector>

namespace violet::mem
{
namespace
{
    std::filesystem::path violet_dir(const wchar_t* subfolder)
    {
        wchar_t*    local  = nullptr;
        std::size_t length = 0;

        if (_wdupenv_s(&local, &length, L"LOCALAPPDATA") != 0 || local == nullptr)
            return {};

        std::filesystem::path dir = std::filesystem::path{ local } / L"Violet" / subfolder;
        std::free(local);

        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        return ec ? std::filesystem::path{} : dir;
    }

    // Is this address range actually safe to read?
    //
    // Not every page of a mapped image is readable. GTA5_Enhanced.exe has two
    // sections (.retplne and .voltbl) whose headers carry no MEM_READ flag at
    // all. Touching those would fault, and a fault inside the game's own
    // process is a crash the player sees - so we ask the kernel first.
    bool readable(const void* address, std::size_t size)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
            return false;

        if (mbi.State != MEM_COMMIT)
            return false;

        constexpr DWORD readable_flags = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                         PAGE_EXECUTE_WRITECOPY;

        if ((mbi.Protect & readable_flags) == 0)
            return false;

        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
            return false;

        // The region has to actually cover what we asked about.
        const auto start = reinterpret_cast<std::uintptr_t>(address);
        const auto end   = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        return start + size <= end;
    }
}

// ---------------------------------------------------------------------------
// compare_text_with_disk
// ---------------------------------------------------------------------------

DiskCompare compare_text_with_disk()
{
    DiskCompare result;

    const auto info = violet::process::inspect(nullptr);
    if (!info)
    {
        result.detail = "could not read PE headers";
        return result;
    }

    const auto code = info->executable_sections();
    if (code.empty())
    {
        result.detail = "no executable sections";
        return result;
    }

    std::ifstream file{ info->path, std::ios::binary };
    if (!file)
    {
        result.detail = "could not open the file on disk";
        return result;
    }

    // Re-read the headers from the FILE, because we need PointerToRawData -
    // where the section lives on disk, which is not where it lives in memory.
    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        result.detail = "bad DOS header on disk";
        return result;
    }

    file.seekg(dos.e_lfanew, std::ios::beg);

    IMAGE_NT_HEADERS64 nt{};
    file.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (!file || nt.Signature != IMAGE_NT_SIGNATURE)
    {
        result.detail = "bad NT headers on disk";
        return result;
    }

    const std::uintptr_t wanted_rva = code.front()->start - info->base;

    std::streamoff raw_offset = 0;
    std::size_t    raw_size   = 0;

    for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER section{};
        file.read(reinterpret_cast<char*>(&section), sizeof(section));
        if (!file)
            break;

        if (section.VirtualAddress == wanted_rva)
        {
            raw_offset = section.PointerToRawData;
            raw_size   = section.SizeOfRawData;
            break;
        }
    }

    if (raw_size == 0)
    {
        result.detail = "could not locate that section in the file";
        return result;
    }

    const std::size_t compare_size = (std::min)(raw_size, code.front()->size);

    std::vector<std::uint8_t> on_disk(compare_size);
    file.seekg(raw_offset, std::ios::beg);
    file.read(reinterpret_cast<char*>(on_disk.data()),
              static_cast<std::streamsize>(compare_size));
    if (!file)
    {
        result.detail = "short read from disk";
        return result;
    }

    const auto* in_memory = reinterpret_cast<const std::uint8_t*>(code.front()->start);

    std::size_t differing = 0;
    for (std::size_t i = 0; i < compare_size; ++i)
        if (in_memory[i] != on_disk[i])
            ++differing;

    result.ok        = true;
    result.compared  = compare_size;
    result.differing = differing;
    result.percent   = 100.0 * static_cast<double>(differing) / static_cast<double>(compare_size);

    if (result.percent < 1.0)
        result.detail = "essentially identical - the file on disk is honest, "
                        "so IDA failing is a different problem";
    else if (result.percent < 15.0)
        result.detail = "mostly matching. Relocations and hooks explain a few percent; "
                        "this is roughly normal";
    else
        result.detail = "substantially different - the code is transformed at runtime, "
                        "so only a memory dump is worth disassembling";

    return result;
}

// ---------------------------------------------------------------------------
// dump_module
// ---------------------------------------------------------------------------

DumpResult dump_module()
{
    DumpResult result;

    const auto info = violet::process::inspect(nullptr);
    if (!info)
    {
        result.detail = "could not read PE headers";
        return result;
    }

    const std::filesystem::path dir = violet_dir(L"dumps");
    if (dir.empty())
    {
        result.detail = "could not create the dumps folder";
        return result;
    }

    const auto* base = reinterpret_cast<const std::uint8_t*>(info->base);

    // Copy the whole mapped image, page by page, skipping anything the kernel
    // says we must not touch. Unreadable pages become zeroes rather than a
    // crash the player gets to see.
    std::vector<std::uint8_t> image(info->size, 0);

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize;

    std::size_t copied  = 0;
    std::size_t skipped = 0;

    for (std::size_t offset = 0; offset < info->size; offset += page)
    {
        const std::size_t chunk = (std::min)(page, info->size - offset);

        if (readable(base + offset, chunk))
        {
            std::memcpy(image.data() + offset, base + offset, chunk);
            copied += chunk;
        }
        else
        {
            skipped += chunk;
        }
    }

    // ---- rewrite the section headers to describe the mapped layout ----
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        result.detail = "dumped image has no MZ header";
        return result;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        result.detail = "dumped image has no PE header";
        return result;
    }

    // The loader overwrote ImageBase in memory with wherever it actually loaded
    // us. Put the ORIGINAL back, so the dump opens in IDA at 0x140000000 and
    // every address matches the notes and the live process.
    nt->OptionalHeader.ImageBase = info->preferred_base;

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        section->PointerToRawData = section->VirtualAddress;
        section->SizeOfRawData    = section->Misc.VirtualSize;
    }

    const std::filesystem::path out = dir / L"GTA5_Enhanced_dumped.exe";

    std::ofstream file{ out, std::ios::binary | std::ios::trunc };
    if (!file)
    {
        result.detail = "could not open the output file";
        return result;
    }

    file.write(reinterpret_cast<const char*>(image.data()),
               static_cast<std::streamsize>(image.size()));
    if (!file)
    {
        result.detail = "write failed - out of disk space?";
        return result;
    }
    file.close();

    result.ok    = true;
    result.bytes = image.size();
    result.path  = out.string();
    result.detail = std::format("{:.1f} MB copied, {:.1f} MB unreadable and zeroed",
                                static_cast<double>(copied) / (1024.0 * 1024.0),
                                static_cast<double>(skipped) / (1024.0 * 1024.0));

    VIOLET_INFO("dumped module to {} ({})", result.path, result.detail);
    return result;
}
}
