#pragma once
//
// Violet - finding GTA's native registration table
//
// ---------------------------------------------------------------------------
// What we are looking for
// ---------------------------------------------------------------------------
//
// GTA's scripts do not call engine functions directly. They call "natives" by
// a 64-bit hash, and the engine looks that hash up in a registration table to
// get the address of the C++ function implementing it. Find that table and you
// can call any of the ~5-6000 natives yourself. That is the entire foundation
// of a mod menu.
//
// The structure, as it has looked in every RAGE title of this lineage:
//
//     struct NativeRegistration
//     {
//         NativeRegistration* next;        // +0x00  linked list
//         NativeHandler       handlers[7]; // +0x08  pointers to actual code
//         uint32_t            count;       // +0x40  how many of the 7 are used
//         uint32_t            _pad;        // +0x44
//         uint64_t            hashes[7];   // +0x48
//     };                                   //  size 0x80
//
//     static NativeRegistration* table[256];   // indexed by hash & 0xFF
//
// ---------------------------------------------------------------------------
// How we find it without knowing where it is
// ---------------------------------------------------------------------------
//
// We do not search for bytes. We search for a SHAPE, which survives compiler
// changes, game updates, and the fact that Enhanced is built with Clang rather
// than MSVC.
//
// The shape is unmistakable: a block of memory containing several consecutive
// pointers that all land inside executable code, followed by a small integer
// saying how many of them are real. Ordinary data almost never looks like that
// - a run of four valid code pointers in a row is already rare, seven is
// essentially unheard of.
//
// So:
//   1. Snapshot which memory is readable and which is executable.
//   2. Sweep the module's data sections. Every 8-byte value is a candidate
//      pointer to a registration block; test each one against the shape.
//   3. The table is 256 consecutive slots of those. Find the densest window.
//   4. Walk it and count. GTA has roughly 5-6000 natives - if the total lands
//      in that range, we have the real thing and not a coincidence.
//
// Step 4 is the verification, and it is why this needs no known hashes to be
// trustworthy. Nothing else in a process is a 256-entry table of linked lists
// of code pointers totalling five thousand entries.
//
// If the layout has changed, probe_layouts() works out the real offsets
// empirically instead of guessing, by recording where the code-pointer runs
// actually start.
//
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace violet::game
{
    struct NativeTableScan
    {
        bool           found     = false;
        std::uintptr_t table     = 0;   // runtime address of the table
        std::uintptr_t table_rva = 0;   // durable form: table - module base
        std::size_t    slots     = 0;   // table slots holding a valid block
        std::size_t    blocks    = 0;   // blocks reached by walking every chain
        std::size_t    natives   = 0;   // total registered natives
        double         elapsed_ms = 0.0;
        std::string    detail;

        // A few (hash, handler) pairs, purely so the log shows something
        // concrete to sanity-check.
        struct Sample { std::uint64_t hash; std::uintptr_t handler; };
        std::vector<Sample> samples;
    };

    NativeTableScan find_native_table();

    // Diagnostic. Run when find_native_table() comes back empty: reports where
    // runs of consecutive executable pointers actually begin inside candidate
    // blocks, which reveals the real handler-array offset rather than assuming
    // the historical 0x08.
    void probe_layouts();

    // The decisive diagnostic.
    //
    // Rather than guessing at a structure layout, take a native hash we know
    // for certain (verified against the CitizenFX native database), find that
    // exact 64-bit value in memory, and print everything around it - marking
    // which neighbouring qwords point at executable code.
    //
    // Whatever the registration block looks like in this build, this shows it
    // directly. And if the hash cannot be found in plaintext anywhere, that is
    // equally informative: it means the hashes are encrypted in memory, which
    // changes the approach entirely.
    //
    // Expect several hits. Loaded script bytecode references natives by hash
    // too, so the interesting one is whichever hit sits next to code pointers.
    void hunt_known_hashes();

    // Find the table by the one property a vtable cannot imitate: registration
    // blocks form a linked list of identically-shaped blocks. Tries several
    // candidate handler-array offsets and prints the raw contents of whatever
    // it finds, so the real layout can be read off rather than assumed.
    void hunt_chains();

    // Closes a gap in the scans above: they all assumed the module's .data
    // points straight at registration blocks. If the 256-entry table is itself
    // heap-allocated, that is two levels of indirection and every earlier scan
    // would have missed it. Looks for long runs of pointers into heap, making
    // no assumption whatsoever about what they point to.
    void hunt_pointer_tables();

    // Dump several entries of a specific table, given its RVA. Used to read a
    // structure's real layout off the screen rather than deducing it from a
    // single sample - which is how the "+0x08 is the next pointer" mistake
    // happened.
    void inspect_table(std::uintptr_t rva, std::size_t entries_to_dump = 4);

    // Brute-force the obfuscated chain pointer.
    //
    // +0x00 and +0x08 hold the "next block" address as an obfuscated pair.
    // Rather than guess the recombination, try every plausible one against all
    // 256 buckets: a wrong formula yields garbage, the right one yields a valid
    // registration block nearly every time.
    void crack_chain(std::uintptr_t table_rva);

    // -----------------------------------------------------------------------
    // The real thing
    // -----------------------------------------------------------------------
    //
    // The registration structure, decoded from GTA's own registerNative()
    // (sub_140920D70 in the memory dump). Layout, for a 0x100-byte block:
    //
    //   +0x00  u32   nextLow  ^ mask
    //   +0x04  u32   nextHigh ^ mask          mask = (u32)block ^ [0x08]
    //   +0x08  u32   key
    //   +0x10  ptr   handlers[7]              PLAINTEXT
    //   +0x48  u32   count ^ (u32)&[0x48] ^ [0x4C]
    //   +0x4C  u32   key
    //   +0x54  u32   hashLow  ^ m   \
    //   +0x58  u32   hashHigh ^ m    >  per entry, stride 16
    //   +0x5C  u32   key             /   m = (u32)&[0x54+i*16] ^ [0x5C+i*16]
    //
    // The obfuscation keys are produced by an LCG (x*0x343FD + 0x269EC3) and
    // are stored right beside the values they hide - so nothing needs breaking,
    // only reading in the right order.
    //
    // Crucially each mask folds in the ADDRESS of the field it protects. That
    // is why no fixed formula could ever recover the pointer: the mask is
    // different for every block, and for every entry within a block.
    struct NativeEntry
    {
        std::uint64_t  hash    = 0;
        std::uintptr_t handler = 0;
    };

    struct DecodedTable
    {
        bool           ok        = false;
        std::uintptr_t table     = 0;
        std::uintptr_t table_rva = 0;
        std::size_t    blocks    = 0;
        std::size_t    natives   = 0;
        double         elapsed_ms = 0.0;
        std::string    detail;
    };

    // Walk and decode the whole table. Pass 0 to locate it automatically.
    DecodedTable decode_native_table(std::uintptr_t table_rva = 0);

    // Resolve one native's handler by hash. Returns 0 if unknown.
    std::uintptr_t find_native_handler(std::uint64_t hash);

    // Everything decoded, for dumping.
    const std::vector<NativeEntry>& decoded_natives();
}
