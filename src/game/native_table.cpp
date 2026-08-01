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
    // The layout, established empirically against GTA V Enhanced 1.0.1158.13.
    //
    //     +0x00   uint64    obfuscated (a hash, or the count - see below)
    //     +0x08   pointer   next registration block
    //     +0x10   handler   \
    //     ...                > seven, stored as plain code pointers
    //     +0x40   handler   /
    //     +0x48   uint64    \
    //     ...                > encrypted hashes
    //
    // This is the historical RAGE structure shifted eight bytes: classically
    // `next` sat at +0x00 with handlers from +0x08. Getting that wrong is why
    // the first three hunts failed - the chain search did test handlers at
    // +0x10, but followed `next` from +0x00, so every chain died at length 2.
    //
    // Note what IS and is not obfuscated. The hashes are encrypted (a plaintext
    // sweep of all 7.6 GB found only our own probe's constants), but the
    // handlers are stored as ordinary pointers into executable memory. That
    // asymmetry is what makes the table findable at all: we cannot search for
    // a hash, but we can absolutely recognise seven consecutive code pointers.
    constexpr std::size_t k_offset_next     = 0x08;
    constexpr std::size_t k_offset_handlers = 0x10;
    constexpr std::size_t k_offset_hashes   = 0x48;
    constexpr std::size_t k_block_size      = 0x88;
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

    // How many handlers does this block actually hold?
    //
    // We count valid code pointers rather than trusting a count field, because
    // we have not yet identified where the count lives - the value at +0x00 is
    // obfuscated along with the hashes. Counting works regardless, and a block
    // is full (7) in every case except the last of a chain.
    std::size_t handler_count(std::uintptr_t block, const violet::mem::RegionMap& regions)
    {
        std::size_t n = 0;
        while (n < k_max_entries &&
               regions.executable(read<std::uintptr_t>(block + k_offset_handlers + n * 8)))
            ++n;
        return n;
    }

    bool looks_like_block(std::uintptr_t address, const violet::mem::RegionMap& regions)
    {
        if (address == 0 || (address & 7) != 0)
            return false;

        if (!regions.readable(address, k_block_size))
            return false;

        // At least one handler pointing at real code. This is the load-bearing
        // test - it is the thing ordinary data cannot fake.
        if (handler_count(address, regions) == 0)
            return false;

        // The chain pointer must be null or lead somewhere readable.
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

            ++blocks;
            natives += handler_count(block, regions);

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

    // The table is a static array, so it lives in the module's own writable
    // data. Sweep those sections; the blocks it points at are on the heap and
    // get validated as we go.
    //
    // Note we gather ALL plausible windows rather than keeping only the densest
    // one. Density alone picked the wrong table on the first attempt - a
    // 256-slot window scored full marks while walking out to just 10 natives.
    // The real discriminator is the size of the structure once you follow it,
    // so every candidate gets walked and the biggest wins.
    std::vector<std::uintptr_t> candidates;

    for (const auto& section : info->sections)
    {
        if (section.executable() || !section.writable() || section.size < k_table_slots * 8)
            continue;

        const std::size_t slots = section.size / 8;

        // One pass to mark which slots hold something block-shaped. Doing this
        // into a flat array turns the window search into a linear sweep rather
        // than 256 re-tests per position.
        std::vector<std::uint8_t> valid(slots, 0);
        for (std::size_t i = 0; i < slots; ++i)
        {
            const auto target = read<std::uintptr_t>(section.start + i * 8);

            // Deliberately loose: any block with at least one real handler.
            //
            // Demanding a mostly-full block here was wrong and found nothing.
            // Registrations are pushed onto the FRONT of each bucket's chain,
            // so the block a table slot points directly at is the partially
            // filled one - often holding just one or two handlers. The full
            // blocks are further down the chain. Filtering on fullness at this
            // level rejects almost every bucket.
            //
            // Precision comes from walking each candidate instead.
            valid[i] = looks_like_block(target, regions) ? 1 : 0;
        }

        std::size_t running = 0;
        for (std::size_t i = 0; i < k_table_slots; ++i)
            running += valid[i];

        std::size_t skip_until = 0;
        if (running >= 200)
        {
            candidates.push_back(section.start);
            skip_until = k_table_slots;
        }

        for (std::size_t i = k_table_slots; i < slots; ++i)
        {
            running += valid[i];
            running -= valid[i - k_table_slots];

            if (running >= 200 && i >= skip_until)
            {
                candidates.push_back(section.start + (i - k_table_slots + 1) * 8);
                skip_until = i + k_table_slots;   // don't report 256 overlapping copies
            }
        }

        VIOLET_INFO("  swept {:<10} {} slots", section.name, slots);
    }

    VIOLET_INFO("  {} candidate table(s)", candidates.size());

    if (candidates.empty())
    {
        result.elapsed_ms = timer.ms();
        result.detail = "no 256-slot window of registration-shaped blocks found";
        return result;
    }

    // ---- walk every candidate; the real table is by far the largest ----
    std::uintptr_t best_at      = 0;
    std::size_t    best_natives = 0;
    std::size_t    best_blocks  = 0;

    for (const auto candidate : candidates)
    {
        std::unordered_set<std::uintptr_t> seen;
        std::size_t blocks = 0, natives = 0;
        std::vector<NativeTableScan::Sample> ignored;

        for (std::size_t i = 0; i < k_table_slots; ++i)
        {
            const auto slot = read<std::uintptr_t>(candidate + i * 8);
            if (slot != 0)
                walk_chain(slot, regions, seen, blocks, natives, ignored);
        }

        VIOLET_INFO("    0x{:X} (RVA 0x{:X}) -> {} blocks, {} natives",
                    candidate, candidate - info->base, blocks, natives);

        if (natives > best_natives)
        {
            best_natives = natives;
            best_blocks  = blocks;
            best_at      = candidate;
        }
    }

    // Re-walk the winner to collect samples for the log.
    {
        std::unordered_set<std::uintptr_t> seen;
        std::size_t blocks = 0, natives = 0;
        for (std::size_t i = 0; i < k_table_slots; ++i)
        {
            const auto slot = read<std::uintptr_t>(best_at + i * 8);
            if (slot != 0)
                walk_chain(slot, regions, seen, blocks, natives, result.samples);
        }
    }

    const std::size_t natives = best_natives;

    result.table      = best_at;
    result.table_rva  = best_at - info->base;
    result.slots      = k_table_slots;
    result.blocks     = best_blocks;
    result.natives    = best_natives;
    result.elapsed_ms = timer.ms();

    if (natives >= k_plausible_min && natives <= k_plausible_max)
    {
        result.found  = true;
        result.detail = std::format("{} natives across {} blocks - within the expected range",
                                    natives, best_blocks);
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
// inspect_table
// ---------------------------------------------------------------------------

void inspect_table(std::uintptr_t rva, std::size_t entries_to_dump)
{
    violet::mem::RegionMap regions;
    regions.rebuild();

    const auto info = violet::process::inspect(nullptr);
    if (!info)
        return;

    const std::uintptr_t table = info->base + rva;

    VIOLET_INFO("--- inspect table at RVA 0x{:X} ---------------------", rva);
    VIOLET_INFO("  runtime 0x{:X}   IDA 0x{:X}", table, 0x140000000ull + rva);
    VIOLET_INFO("  Dumping several entries. Deducing the layout from ONE block");
    VIOLET_INFO("  was a mistake - the field at +0x08 is unaligned, so it is not");
    VIOLET_INFO("  a pointer at all. Comparing entries shows which fields are");
    VIOLET_INFO("  structural and which are encrypted noise.");

    // Spread the samples across the table rather than taking the first few in a
    // row; adjacent buckets can be unrepresentative.
    const std::size_t stride = (k_table_slots / (entries_to_dump ? entries_to_dump : 1));

    for (std::size_t e = 0; e < entries_to_dump; ++e)
    {
        const std::size_t index = e * stride;
        const auto block = read<std::uintptr_t>(table + index * 8);

        VIOLET_INFO("");
        VIOLET_INFO("  slot[{}] -> 0x{:X}{}", index, block,
                    regions.is_private(block) ? "  (heap)" : "");

        if (!regions.readable(block, 0x100))
        {
            VIOLET_INFO("    not readable");
            continue;
        }

        for (int slot = 0; slot < 32; ++slot)
        {
            const std::uintptr_t address = block + static_cast<std::size_t>(slot) * 8;
            if (!regions.readable(address, 8))
                break;

            const auto value = read<std::uint64_t>(address);
            const auto as_ptr = static_cast<std::uintptr_t>(value);

            const char* tag = "";
            if (regions.executable(as_ptr))
                tag = "  CODE";
            else if (value != 0 && (value & 7) == 0 && regions.readable(as_ptr, 0x40))
                tag = regions.is_private(as_ptr) ? "  aligned heap ptr" : "  aligned ptr";
            else if (value != 0 && value < 64)
                tag = "  small int";

            VIOLET_INFO("    +0x{:02X}  0x{:016X}{}", slot * 8, value, tag);
        }
    }
}

// ---------------------------------------------------------------------------
// hunt_pointer_tables
// ---------------------------------------------------------------------------

void hunt_pointer_tables()
{
    violet::mem::RegionMap regions;
    regions.rebuild();

    const auto info = violet::process::inspect(nullptr);
    if (!info)
        return;

    VIOLET_INFO("--- pointer-table hunt ------------------------------");
    VIOLET_INFO("  Everything so far assumed .data points straight AT the");
    VIOLET_INFO("  registration blocks. If the 256-entry table is itself heap");
    VIOLET_INFO("  allocated, that is two levels of indirection and every scan");
    VIOLET_INFO("  so far would have missed it. Looking for long runs of");
    VIOLET_INFO("  pointers into heap - no assumption about what they point to.");

    constexpr std::size_t k_min_run = 128;

    const Timer timer;

    struct Found { std::uintptr_t start; std::size_t length; };
    std::vector<Found> candidates;

    const auto sweep = [&](std::uintptr_t begin, std::uintptr_t end)
    {
        std::size_t run = 0;
        std::uintptr_t run_start = 0;

        for (std::uintptr_t address = begin; address + 8 <= end; address += 8)
        {
            const auto value = read<std::uintptr_t>(address);

            // Only count pointers into heap. A run of pointers into the
            // module's own data is far more likely to be a relocation table or
            // an array of import thunks than anything we want.
            const bool ok = value != 0 && (value & 7) == 0 &&
                            regions.readable(value, 0x40) &&
                            regions.is_private(value);

            if (ok)
            {
                if (run == 0)
                    run_start = address;
                ++run;
            }
            else
            {
                if (run >= k_min_run)
                    candidates.push_back({ run_start, run });
                run = 0;
            }
        }

        if (run >= k_min_run)
            candidates.push_back({ run_start, run });
    };

    for (const auto& section : info->sections)
    {
        if (section.executable() || !section.writable() || section.size < k_min_run * 8)
            continue;
        sweep(section.start, section.start + section.size);
    }

    VIOLET_INFO("  swept module data in {:.0f} ms, {} candidate run(s) of {}+ heap pointers",
                timer.ms(), candidates.size(), k_min_run);

    // Report the most table-shaped ones. 256 is the number we care about.
    std::size_t shown = 0;
    for (const auto& c : candidates)
    {
        if (shown >= 6)
            break;
        ++shown;

        VIOLET_INFO("");
        VIOLET_INFO("  run of {} at 0x{:X}  (RVA 0x{:X}, IDA 0x{:X})",
                    c.length, c.start, c.start - info->base,
                    0x140000000ull + (c.start - info->base));

        // What does the first entry actually look like? Even with encrypted
        // handlers, the block's SHAPE is visible.
        const auto first = read<std::uintptr_t>(c.start);
        VIOLET_INFO("    first entry -> 0x{:X}, contents:", first);

        for (int slot = 0; slot < 20; ++slot)
        {
            const std::uintptr_t address = first + static_cast<std::size_t>(slot) * 8;
            if (!regions.readable(address, 8))
                break;

            const auto value = read<std::uint64_t>(address);

            const char* tag = "";
            if (regions.executable(static_cast<std::uintptr_t>(value)))
                tag = "  <-- CODE";
            else if (value != 0 && regions.readable(static_cast<std::uintptr_t>(value), 8))
                tag = "  <-- ptr";
            else if (value != 0 && value < 64)
                tag = "  <-- small int";

            VIOLET_INFO("      +0x{:02X}  0x{:016X}{}", slot * 8, value, tag);
        }
    }
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
