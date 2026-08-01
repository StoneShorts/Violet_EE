#pragma once
//
// Violet - signature scanning
//
// ---------------------------------------------------------------------------
// Why patterns instead of addresses
// ---------------------------------------------------------------------------
//
// You could write down "the function I want is at 0x1409A3F40" and be right -
// until the next game update, when the compiler emits one extra instruction
// somewhere earlier and every address after it shifts. Now nothing works, and
// nothing tells you why.
//
// A signature describes the function's *code* instead of its location:
//
//     "48 89 5C 24 ? 57 48 83 EC 20 8B D9 48 8B FA"
//
// Each pair of hex digits is a byte that must match. Each ? is a byte we do
// not care about - and the ones we do not care about are the whole point.
// Those are the bytes most likely to change between builds: relative call
// offsets, RIP-relative displacements, stack frame sizes. Wildcard those, keep
// the opcodes, and the same signature keeps finding the same function across
// updates.
//
// This is what every serious game mod does, and it is why they survive patches
// that break offset lists.
//
// ---------------------------------------------------------------------------
// RIP-relative addressing, the thing everyone gets wrong first
// ---------------------------------------------------------------------------
//
// On x64, code rarely contains absolute addresses. It says "relative to where
// the instruction pointer will be next". So a global access looks like:
//
//     48 8B 05 A1 B2 C3 00      mov rax, [rip + 0x00C3B2A1]
//     ^^^^^^^^ ^^^^^^^^^^^
//     opcode   32-bit signed displacement, at offset 3
//
// The target is NOT instruction + 3 + displacement. The CPU adds the
// displacement to the address of the NEXT instruction, so it is:
//
//     target = instruction_address + instruction_length + displacement
//            = instruction_address + 7 + 0x00C3B2A1
//
// Get that wrong and you land 4 bytes off and read garbage that looks almost
// plausible. resolve_rip() below exists so that arithmetic is written once.
//
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace violet::mem
{
    class Pattern
    {
    public:
        // Accepts IDA-style text: hex byte pairs and ? or ?? for wildcards,
        // separated by whitespace. Returns nullopt if the text is malformed.
        static std::optional<Pattern> parse(std::string_view signature);

        std::size_t        size() const { return m_bytes.size(); }
        const std::string& text() const { return m_text; }

        const std::uint8_t* bytes() const { return m_bytes.data(); }
        const char*         mask()  const { return m_mask.data(); }

        // Index of the first byte that is not a wildcard. Scanning anchors on
        // this byte, so a signature starting with wildcards costs nothing.
        std::size_t anchor()     const { return m_anchor; }
        bool        has_anchor() const { return m_has_anchor; }

        // How many bytes actually have to match. A signature with very few is
        // a signature that will match half the binary.
        std::size_t fixed_count() const;

    private:
        std::vector<std::uint8_t> m_bytes;
        std::vector<char>         m_mask;      // 1 = must match, 0 = wildcard
        std::string               m_text;
        std::size_t               m_anchor     = 0;
        bool                      m_has_anchor = false;
    };

    struct ScanResult
    {
        std::uintptr_t address = 0;

        explicit operator bool() const { return address != 0; }

        // Follow a RIP-relative operand inside the matched instruction.
        //   displacement_offset - where the 32-bit displacement starts
        //   instruction_length  - total length of the whole instruction
        std::uintptr_t rip(int displacement_offset, int instruction_length) const;

        // Address relative to the module base. This is the durable form worth
        // writing down, and what a disassembler shows once you add its base.
        std::uintptr_t rva() const;
        std::uintptr_t ida() const;
    };

    // Search every executable section of the host module.
    ScanResult scan(const Pattern& p);
    ScanResult scan(std::string_view signature);

    std::vector<std::uintptr_t> scan_all(const Pattern& p, std::size_t limit = 256);

    std::uintptr_t resolve_rip(std::uintptr_t instruction,
                               int displacement_offset,
                               int instruction_length);

    // How long the last scan took, and how much ground it covered.
    double      last_scan_ms();
    std::size_t last_scan_bytes();

    // -----------------------------------------------------------------------
    // Finding things when nothing is labelled
    // -----------------------------------------------------------------------
    //
    // A signature is how you RE-find something you have already located. It is
    // no help at all for the first discovery, because you do not yet know what
    // bytes to look for.
    //
    // This is how you get the first foothold. A stripped binary has no function
    // names - but it is full of strings: error messages, asset paths, script
    // names, format strings. Those are effectively labels the developers left
    // behind by accident.
    //
    // So the technique is two steps:
    //
    //   1. find_string()     - locate the text in the read-only data sections
    //   2. find_references() - find the code that points at that address
    //
    // Step 2 works because x64 code loads a global's address with a
    // RIP-relative instruction, so the reference is discoverable by resolving
    // every candidate and checking where it lands. Whatever function contains
    // that instruction is the one that prints, loads, or checks that string -
    // and now you have located a function by what it SAYS, without a single
    // symbol.

    // Search the readable, non-executable sections for an ASCII string.
    std::vector<std::uintptr_t> find_string(std::string_view text, std::size_t limit = 64);

    struct Xref
    {
        std::uintptr_t instruction = 0;
        char           kind        = '?';   // 'L' = lea (take address), 'M' = mov (load value)
    };

    // Find RIP-relative instructions in executable memory that resolve to
    // `target`. Covers the two overwhelmingly common forms:
    //
    //     48 8D 0D xx xx xx xx    lea rcx, [rip+disp]   - take its address
    //     48 8B 05 xx xx xx xx    mov rax, [rip+disp]   - load through it
    //
    // Note this necessarily produces some false positives. x86 instructions are
    // variable length, so without fully disassembling you cannot know where one
    // begins - bytes in the middle of an unrelated instruction can coincidentally
    // look like a RIP-relative load. Most hits are real; verify in a
    // disassembler before trusting one.
    std::vector<Xref> find_references(std::uintptr_t target, std::size_t limit = 64);

    // ---- verification ----
    //
    // Runs at startup. Samples real bytes out of the game's own code, builds a
    // signature from them (with wildcards punched through the middle, so the
    // wildcard path is exercised rather than a plain memcmp), scans for it, and
    // checks the address it came from is among the matches.
    //
    // A scanner that is subtly wrong does not crash - it just quietly fails to
    // find things that are definitely there, and you spend an evening blaming
    // your signature. This makes that impossible to miss.
    struct SelfTest
    {
        bool        passed        = false;
        std::string detail;
        std::size_t matches       = 0;
        double      elapsed_ms    = 0.0;
        std::size_t bytes_scanned = 0;
    };

    SelfTest self_test();
}
