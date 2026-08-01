#pragma once
//
// Violet - dumping the module out of memory
//
// ---------------------------------------------------------------------------
// Why this is necessary
// ---------------------------------------------------------------------------
//
// Loading GTA5_Enhanced.exe straight off disk into a disassembler produces
// mostly nonsense: 16-bit DOS instructions, an "Unexplored" navigator bar, and
// a fraction of the functions that should be there. The binary has been
// processed after linking, and what sits in the file is not what the CPU ends
// up executing.
//
// But we are running INSIDE the process. By the time our code is alive, the
// loader has mapped the image, applied relocations, resolved imports, and any
// protection has already unpacked whatever it unpacks - because the game has to
// execute real instructions eventually. Memory holds the truth.
//
// So: copy the mapped image back out to a file, and disassemble that instead.
//
// ---------------------------------------------------------------------------
// The one fix-up that makes the dump usable
// ---------------------------------------------------------------------------
//
// A PE file on disk and the same PE mapped into memory have DIFFERENT layouts.
// On disk, sections are packed tightly and located by PointerToRawData. Once
// mapped, they are spread out at their VirtualAddress and padded to page
// boundaries.
//
// Dump memory verbatim and every section header still describes the *disk*
// layout, so a disassembler reads each section from the wrong offset and you
// get garbage again - just different garbage.
//
// The fix is to rewrite each section header so it describes the layout the file
// now actually has:
//
//     PointerToRawData = VirtualAddress
//     SizeOfRawData    = VirtualSize
//
// After that the file is self-consistent and IDA loads it correctly.
//
#include <cstddef>
#include <string>

namespace violet::mem
{
    struct DiskCompare
    {
        bool        ok        = false;
        std::size_t compared  = 0;
        std::size_t differing = 0;
        double      percent   = 0.0;
        std::string detail;
    };

    // Compare the first executable section byte-for-byte against the same bytes
    // in the file on disk.
    //
    // Some difference is always expected and does NOT indicate protection: the
    // loader rewrites absolute addresses listed in .reloc, and any overlay that
    // has hooked a function has patched its first few bytes. A few percent of
    // scattered differences is normal. Large contiguous regions are not.
    DiskCompare compare_text_with_disk();

    struct DumpResult
    {
        bool        ok    = false;
        std::size_t bytes = 0;
        std::string path;
        std::string detail;
    };

    // Write the mapped image to %LOCALAPPDATA%\Violet\dumps\, with section
    // headers fixed up so a disassembler can read it.
    DumpResult dump_module();
}
