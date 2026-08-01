#include "game/native_table.hpp"

#include "core/log.hpp"
#include "core/process.hpp"
#include "mem/regions.hpp"

#include <Windows.h>

#include <array>
#include <cstring>
#include <format>
#include <unordered_set>

namespace violet::game
{
namespace
{
    // The historical RAGE layout. Treated as a starting hypothesis, not a fact -
    // probe_layouts() exists precisely because it might be wrong here.
    constexpr std::size_t k_offset_next     = 0x00;
    constexpr std::size_t k_offset_handlers = 0x08;
    constexpr std::size_t k_offset_count    = 0x40;
    constexpr std::size_t k_offset_hashes   = 0x48;
    constexpr std::size_t k_block_size      = 0x80;
    constexpr std::size_t k_max_entries     = 7;

    constexpr std::size_t k_table_slots = 256;

    // GTA V has somewhere around 5-6000 natives. A candidate that walks out to
    // a total in this band is the real table; anything wildly outside it is a
    // coincidence we should reject rather than celebrate.
    constexpr std::size_t k_plausible_min = 2000;
    constexpr std::size_t k_plausible_max = 12000;

    // Every read goes through structured exception handling.
    //
    // We are dereferencing addresses derived from arbitrary bytes in a live
    // game. The region snapshot makes that mostly safe - but the game is
    // allocating and freeing constantly, so memory can stop being valid between
    // the check and the read, and "mostly safe" is the wrong standard when
    // being wrong means crashing someone's session.
    //
    // A function containing __try cannot hold C++ objects that need unwinding,
    // which is why this is a small non-template helper with the template sugar
    // layered on top.
    bool try_read_raw(std::uintptr_t address, void* out, std::size_t size)
    {
        __try
        {
            std::memcpy(out, reinterpret_cast<const void*>(address), size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    template <typename T>
    T read(std::uintptr_t address)
    {
        T value{};
        if (!try_read_raw(address, &value, sizeof(T)))
            return T{};
        return value;
    }

    struct Timer
    {
        LARGE_INTEGER start{}, freq{};
        Timer() { QueryPerformanceFrequency(&freq); QueryPerformanceCounter(&start); }
        double ms() const
        {
            LARGE_INTEGER now{};
            QueryPerformanceCounter(&now);
            return static_cast<double>(now.QuadPart - start.QuadPart) * 1000.0
                 / static_cast<double>(freq.QuadPart);
        }
    };

    // How many consecutive executable pointers sit at `offset` inside a block?
    //
    // Layout-agnostic on purpose. We do not assume the handler array is at
    // +0x08 or that the count is at +0x40, because Enhanced is a Clang build of
    // a newer engine and both may have moved.
    int code_pointer_run(std::uintptr_t block, std::size_t offset,
                         const violet::mem::RegionMap& regions)
    {
        int run = 0;
        while (run < 16)
        {
            const auto handler = read<std::uintptr_t>(block + offset + static_cast<std::size_t>(run) * 8);
            if (!regions.executable(handler))
                break;
            ++run;
        }
        return run;
    }

    // Follow the linked list and report how many blocks of consistent shape it
    // strings together.
    //
    // This is the test that vtables cannot pass. A vtable is a bare run of
    // function pointers - nothing points from one vtable to the next. The
    // native registrations are a chain: every block's first qword is the
    // address of another block with the same internal shape. A chain twenty
    // deep of identically-shaped code-pointer blocks is not something that
    // occurs by accident.
    std::size_t chain_length(std::uintptr_t block, std::size_t handlers_offset,
                             const violet::mem::RegionMap& regions,
                             std::size_t limit = 4096)
    {
        std::size_t length = 0;
        std::uintptr_t seen_first = block;

        while (block != 0 && length < limit)
        {
            if (!regions.readable(block, 0x100))
                break;
            if (code_pointer_run(block, handlers_offset, regions) < 3)
                break;

            ++length;

            const auto next = read<std::uintptr_t>(block + k_offset_next);
            if (next == block || next == seen_first)
                break;   // self-loop or cycle

            block = next;
        }

        return length;
    }

    bool looks_like_block(std::uintptr_t address, const violet::mem::RegionMap& regions)
    {
        if (address == 0 || (address & 7) != 0)
            return false;

        if (!regions.readable(address, k_block_size))
            return false;

        const auto count = read<std::uint32_t>(address + k_offset_count);
        if (count == 0 || count > k_max_entries)
            return false;

        // Every handler the block claims to hold must point at executable code.
        // This is the load-bearing test - it is what ordinary data cannot fake.
        for (std::uint32_t i = 0; i < count; ++i)
        {
            const auto handler = read<std::uintptr_t>(address + k_offset_handlers + i * 8);
            if (!regions.executable(handler))
                return false;
        }

        // The chain pointer must be null or lead somewhere we could read.
        const auto next = read<std::uintptr_t>(address + k_offset_next);
        if (next != 0 && !regions.readable(next, k_block_size))
            return false;

        return true;
    }

    // Follow one slot's chain, counting blocks and entries. Guards against a
    // corrupt or misidentified pointer producing an endless loop.
    void walk_chain(std::uintptr_t block,
                    const violet::mem::RegionMap& regions,
                    std::unordered_set<std::uintptr_t>& seen,
                    std::size_t& blocks,
                    std::size_t& natives,
                    std::vector<NativeTableScan::Sample>& samples)
    {
        std::size_t guard = 0;

        while (block != 0 && guard++ < 4096)
        {
            if (!seen.insert(block).second)
                break;   // already walked; a cycle or a shared tail

            if (!looks_like_block(block, regions))
                break;

            const auto count = read<std::uint32_t>(block + k_offset_count);
            ++blocks;
            natives += count;

            if (samples.size() < 8)
            {
                samples.push_back({
                    read<std::uint64_t>(block + k_offset_hashes),
                    read<std::uintptr_t>(block + k_offset_handlers)
                });
            }

            block = read<std::uintptr_t>(block + k_offset_next);
        }
    }
}

// ---------------------------------------------------------------------------
// find_native_table
// ---------------------------------------------------------------------------

NativeTableScan find_native_table()
{
    NativeTableScan result;
    const Timer timer;

    const auto info = violet::process::inspect(nullptr);
    if (!info)
    {
        result.detail = "could not read PE headers";
        return result;
    }

    violet::mem::RegionMap regions;
    regions.rebuild();

    VIOLET_INFO("native table: {} readable regions, {:.1f} MB total",
                regions.region_count(),
                static_cast<double>(regions.total_bytes()) / (1024.0 * 1024.0));

    // The table itself is a static array, so it lives in the module's own
    // writable data. Sweep those sections; the blocks it points at are on the
    // heap and get validated as we go.
    std::size_t best_hits  = 0;
    std::uintptr_t best_at = 0;

    for (const auto& section : info->sections)
    {
        if (section.executable() || section.size < k_table_slots * 8)
            continue;
        if (!section.writable())
            continue;   // a table of heap pointers has to be writable

        const std::size_t slots = section.size / 8;

        // First pass: which slots hold something block-shaped. Doing this once
        // into a flat array turns the window search below into a cheap linear
        // sweep instead of 256 re-tests per position.
        std::vector<std::uint8_t> valid(slots, 0);

        for (std::size_t i = 0; i < slots; ++i)
        {
            const auto candidate = read<std::uintptr_t>(section.start + i * 8);
            valid[i] = looks_like_block(candidate, regions) ? 1 : 0;
        }

        // Second pass: the densest window of 256 consecutive slots.
        if (slots < k_table_slots)
            continue;

        std::size_t running = 0;
        for (std::size_t i = 0; i < k_table_slots; ++i)
            running += valid[i];

        if (running > best_hits)
        {
            best_hits = running;
            best_at   = section.start;
        }

        for (std::size_t i = k_table_slots; i < slots; ++i)
        {
            running += valid[i];
            running -= valid[i - k_table_slots];

            if (running > best_hits)
            {
                best_hits = running;
                best_at   = section.start + (i - k_table_slots + 1) * 8;
            }
        }

        VIOLET_INFO("  swept {:<10} {} slots", section.name, slots);
    }

    result.elapsed_ms = timer.ms();

    if (best_at == 0 || best_hits < 32)
    {
        result.detail = std::format(
            "no table-shaped region found (best window held only {} valid blocks)",
            best_hits);
        return result;
    }

    // ---- verify by walking it ----
    std::unordered_set<std::uintptr_t> seen;
    std::size_t blocks = 0, natives = 0;

    for (std::size_t i = 0; i < k_table_slots; ++i)
    {
        const auto slot = read<std::uintptr_t>(best_at + i * 8);
        if (slot != 0)
            walk_chain(slot, regions, seen, blocks, natives, result.samples);
    }

    result.table      = best_at;
    result.table_rva  = best_at - info->base;
    result.slots      = best_hits;
    result.blocks     = blocks;
    result.natives    = natives;
    result.elapsed_ms = timer.ms();

    if (natives >= k_plausible_min && natives <= k_plausible_max)
    {
        result.found  = true;
        result.detail = std::format("{} natives across {} blocks - within the expected range",
                                    natives, blocks);
    }
    else
    {
        result.detail = std::format(
            "found a table-shaped region with {} entries, which is outside the "
            "plausible {}-{} range - probably a coincidence, or the layout differs",
            natives, k_plausible_min, k_plausible_max);
    }

    return result;
}

// ---------------------------------------------------------------------------
// hunt_chains
// ---------------------------------------------------------------------------

void hunt_chains()
{
    violet::mem::RegionMap regions;
    regions.rebuild();

    const auto info = violet::process::inspect(nullptr);
    if (!info)
        return;

    VIOLET_INFO("--- chain hunt --------------------------------------");
    VIOLET_INFO("  A vtable is a bare run of function pointers - nothing links");
    VIOLET_INFO("  one to the next. Native registrations are a CHAIN. Looking");
    VIOLET_INFO("  for long chains of identically-shaped code-pointer blocks.");

    constexpr std::size_t k_offsets[] = { 0x08, 0x10, 0x18, 0x20 };

    struct Best { std::size_t length = 0; std::uintptr_t block = 0; std::uintptr_t slot = 0; };
    Best best[std::size(k_offsets)];
    std::size_t chains_over_8[std::size(k_offsets)]{};

    const Timer timer;

    for (const auto& section : info->sections)
    {
        if (section.executable() || !section.writable() || section.size < 4096)
            continue;

        const std::size_t slots = section.size / 8;

        for (std::size_t i = 0; i < slots; ++i)
        {
            const auto target = read<std::uintptr_t>(section.start + i * 8);

            if (target == 0 || (target & 7) != 0)
                continue;
            if (!regions.readable(target, 0x100))
                continue;

            // One readability check, then try every candidate layout against
            // it - far cheaper than re-walking the section per offset.
            for (std::size_t k = 0; k < std::size(k_offsets); ++k)
            {
                if (code_pointer_run(target, k_offsets[k], regions) < 3)
                    continue;

                const std::size_t length = chain_length(target, k_offsets[k], regions);
                if (length >= 8)
                    ++chains_over_8[k];

                if (length > best[k].length)
                {
                    best[k].length = length;
                    best[k].block  = target;
                    best[k].slot   = section.start + i * 8;
                }
            }
        }
    }

    VIOLET_INFO("  swept in {:.0f} ms", timer.ms());

    for (std::size_t k = 0; k < std::size(k_offsets); ++k)
    {
        VIOLET_INFO("");
        VIOLET_INFO("  handlers at +0x{:02X} : longest chain {} blocks, {} chains of 8+",
                    k_offsets[k], best[k].length, chains_over_8[k]);

        if (best[k].length < 8)
            continue;

        VIOLET_INFO("    table slot 0x{:X}  (RVA 0x{:X}, IDA 0x{:X})",
                    best[k].slot, best[k].slot - info->base,
                    0x140000000ull + (best[k].slot - info->base));
        VIOLET_INFO("    first block 0x{:X}", best[k].block);
        VIOLET_INFO("    raw contents of that block:");

        // Print it verbatim. Whatever the real layout is, it is visible here.
        for (int slot = 0; slot < 24; ++slot)
        {
            const std::uintptr_t address = best[k].block + static_cast<std::size_t>(slot) * 8;
            if (!regions.readable(address, 8))
                break;

            const auto value = read<std::uint64_t>(address);

            const char* tag = "";
            if (regions.executable(static_cast<std::uintptr_t>(value)))
                tag = "  <-- CODE";
            else if (value != 0 && regions.readable(static_cast<std::uintptr_t>(value), 8))
                tag = "  <-- ptr";
            else if (value != 0 && value < 64)
                tag = "  <-- small int (a count?)";

            VIOLET_INFO("      +0x{:02X}  0x{:016X}{}", slot * 8, value, tag);
        }
    }
}

// ---------------------------------------------------------------------------
// hunt_known_hashes
// ---------------------------------------------------------------------------

namespace
{
    // Verified against the CitizenFX native database rather than recalled.
    // Getting one hex digit wrong here would make the search silently fail and
    // send us to entirely the wrong conclusion.
    struct KnownNative { const char* name; std::uint64_t hash; };

    constexpr KnownNative k_known[] = {
        { "GET_PLAYER_PED",    0x43A66C31C68491C0ull },
        { "SET_ENTITY_COORDS", 0x06843DA7060A026Bull },
    };

    // Raw scan of one region. Deliberately contains no C++ objects, because a
    // function using __try cannot hold anything that needs unwinding.
    std::size_t scan_region_for_qword(const std::uint64_t* begin,
                                      std::size_t count,
                                      std::uint64_t value,
                                      std::uintptr_t* out,
                                      std::size_t capacity)
    {
        std::size_t found = 0;

        __try
        {
            for (std::size_t i = 0; i < count; ++i)
            {
                if (begin[i] == value)
                {
                    if (found < capacity)
                        out[found] = reinterpret_cast<std::uintptr_t>(begin + i);
                    ++found;
                    if (found >= capacity)
                        break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // Region went away mid-scan. Whatever we found before that stands.
        }

        return found;
    }
}

void hunt_known_hashes()
{
    violet::mem::RegionMap regions;
    regions.rebuild();

    VIOLET_INFO("--- known-hash hunt ---------------------------------");
    VIOLET_INFO("  Searching heap memory for native hashes we know are correct,");
    VIOLET_INFO("  then printing what surrounds each hit.");
    VIOLET_INFO("  {:.1f} MB private of {:.1f} MB readable",
                static_cast<double>(regions.private_bytes()) / (1024.0 * 1024.0),
                static_cast<double>(regions.total_bytes()) / (1024.0 * 1024.0));

    const auto info = violet::process::inspect(nullptr);

    for (const auto& known : k_known)
    {
        VIOLET_INFO("");
        VIOLET_INFO("  {}  =  0x{:016X}", known.name, known.hash);

        constexpr std::size_t k_capacity = 64;
        std::uintptr_t hits[k_capacity]{};
        std::size_t total = 0;
        std::size_t stored = 0;

        // Walk regions via the snapshot. Scanning aligned qwords only, since a
        // hash inside a struct is aligned - and it makes the sweep 8x cheaper.
        const Timer timer;

        for (std::size_t r = 0; r < regions.region_count(); ++r)
        {
            std::uintptr_t start = 0, end = 0;
            bool is_private = false;
            if (!regions.region_at(r, start, end, &is_private))
                continue;

            // Heap only. The mapped regions are asset archives and textures -
            // gigabytes of them - and paging those in from disk to look for a
            // struct that cannot possibly be there is both slow and unkind to a
            // game that is trying to use that same paging bandwidth.
            const bool in_module = info && start >= info->base &&
                                   start < info->base + info->size;
            if (!is_private && !in_module)
                continue;

            const auto* base = reinterpret_cast<const std::uint64_t*>(start);
            const std::size_t count = (end - start) / 8;

            const std::size_t room = (stored < k_capacity) ? (k_capacity - stored) : 0;
            const std::size_t n = scan_region_for_qword(base, count, known.hash,
                                                        hits + stored, room);
            total  += n;
            stored += (n < room) ? n : room;
        }

        VIOLET_INFO("    {} occurrence(s), swept in {:.0f} ms", total, timer.ms());

        if (total == 0)
        {
            VIOLET_WARN("    Not present in plaintext anywhere. The hashes are");
            VIOLET_WARN("    stored encrypted, so the table cannot be found by");
            VIOLET_WARN("    searching for them - we need the decrypt routine.");
            continue;
        }

        // Print the neighbourhood of the first few hits. The one we want is
        // whichever sits among pointers into executable code.
        const std::size_t to_show = (stored < 4) ? stored : 4;

        for (std::size_t h = 0; h < to_show; ++h)
        {
            const std::uintptr_t at = hits[h];
            VIOLET_INFO("");
            VIOLET_INFO("    hit #{} at 0x{:X}{}", h, at,
                        (info && at >= info->base && at < info->base + info->size)
                            ? "  (inside the module)" : "  (heap)");

            // Sixteen qwords either side, annotated. CODE markers are the
            // giveaway: a registration block has a run of them.
            for (int slot = -12; slot <= 12; ++slot)
            {
                const std::uintptr_t address = at + static_cast<std::intptr_t>(slot) * 8;
                if (!regions.readable(address, 8))
                    continue;

                const auto value = read<std::uint64_t>(address);

                const char* tag = "";
                if (regions.executable(static_cast<std::uintptr_t>(value)))
                    tag = "  <-- CODE";
                else if (value != 0 && regions.readable(static_cast<std::uintptr_t>(value), 8))
                    tag = "  <-- ptr";

                VIOLET_INFO("      {:+04d}  0x{:016X}{}{}",
                            slot * 8, value, tag,
                            slot == 0 ? "   *** the hash ***" : "");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// probe_layouts
// ---------------------------------------------------------------------------

void probe_layouts()
{
    const auto info = violet::process::inspect(nullptr);
    if (!info)
        return;

    violet::mem::RegionMap regions;
    regions.rebuild();

    VIOLET_INFO("--- layout probe ------------------------------------");
    VIOLET_INFO("  Looking for runs of consecutive executable pointers inside");
    VIOLET_INFO("  anything the module's data sections point at. Wherever those");
    VIOLET_INFO("  runs begin IS the handler array offset, whatever it is.");

    // offset -> how many blocks had a run of >=4 code pointers starting there
    std::array<std::size_t, 32> histogram{};
    std::size_t examined = 0;
    std::size_t longest  = 0;

    for (const auto& section : info->sections)
    {
        if (section.executable() || !section.writable())
            continue;

        const std::size_t slots = section.size / 8;

        for (std::size_t i = 0; i < slots; ++i)
        {
            const auto target = read<std::uintptr_t>(section.start + i * 8);

            if (target == 0 || (target & 7) != 0)
                continue;
            if (!regions.readable(target, 0x100))
                continue;

            ++examined;

            // Where does the longest run of executable pointers start?
            for (std::size_t offset = 0; offset < histogram.size(); ++offset)
            {
                std::size_t run = 0;
                while (run < 16 &&
                       regions.executable(read<std::uintptr_t>(target + (offset + run) * 8)))
                    ++run;

                if (run >= 4)
                {
                    ++histogram[offset];
                    longest = (run > longest) ? run : longest;
                    break;   // record only where the run starts
                }
            }
        }
    }

    VIOLET_INFO("  examined {} pointer targets, longest code-pointer run {}",
                examined, longest);

    for (std::size_t offset = 0; offset < histogram.size(); ++offset)
        if (histogram[offset] > 0)
            VIOLET_INFO("    run starts at +0x{:02X}  ->  {} blocks",
                        offset * 8, histogram[offset]);
}
}
