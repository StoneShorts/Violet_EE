#pragma once
//
// Violet - a snapshot of what memory is safe to touch
//
// The native table hunt involves testing millions of candidate pointers. Each
// test needs to answer "can I read this address without crashing the game?"
//
// The honest way to ask is VirtualQuery - but it is a system call, and calling
// it five million times would take minutes. So we call it once per memory
// region up front, cache the answers in a sorted array, and then answer each
// question with a binary search.
//
// The snapshot goes stale the moment the game allocates or frees anything, so
// it is rebuilt at the start of every scan rather than kept around. For a scan
// that takes a second or two, that is accurate enough - and every dereference
// is still bounds-checked against it, so a stale entry costs a wrong answer
// rather than a crash.
//
#include <cstddef>
#include <cstdint>
#include <vector>

namespace violet::mem
{
    class RegionMap
    {
    public:
        // Walk the whole user-mode address space and record every committed,
        // readable region.
        void rebuild();

        // Is [address, address + size) entirely inside one readable region?
        bool readable(std::uintptr_t address, std::size_t size) const;

        // Is it readable AND executable? This is the test that matters for
        // native handlers - a handler must point at code.
        bool executable(std::uintptr_t address) const;

        std::size_t region_count()  const { return m_regions.size(); }
        std::size_t total_bytes()   const { return m_total; }

        // Enumerate regions, for callers that want to sweep memory rather than
        // test individual addresses.
        //
        // `private_only` matters more than it looks. A running GTA has ~7.6 GB
        // of readable memory, but the overwhelming bulk of that is MEM_MAPPED -
        // memory-mapped asset archives, textures, models. Sweeping those forces
        // gigabytes of cold pages in from disk: painfully slow, and it steals
        // the paging bandwidth the game is trying to use.
        //
        // Heap allocations - which is where anything like a registration block
        // lives - are MEM_PRIVATE. Restricting to those cuts the search space
        // by well over an order of magnitude and loses nothing we want.
        bool region_at(std::size_t index, std::uintptr_t& start, std::uintptr_t& end,
                       bool* is_private = nullptr) const;

        std::size_t private_bytes() const { return m_private; }

    private:
        struct Region
        {
            std::uintptr_t start    = 0;
            std::uintptr_t end      = 0;
            bool           exec     = false;
            bool           is_private = false;   // MEM_PRIVATE: heap, not a mapped file
        };

        const Region* find(std::uintptr_t address) const;

        std::vector<Region> m_regions;   // sorted by start
        std::size_t         m_total   = 0;
        std::size_t         m_private = 0;
    };
}
