#include "mem/regions.hpp"

#include <Windows.h>

#include <algorithm>

namespace violet::mem
{
namespace
{
    constexpr DWORD k_readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                 PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                 PAGE_EXECUTE_WRITECOPY;

    constexpr DWORD k_executable = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
}

void RegionMap::rebuild()
{
    m_regions.clear();
    m_total = 0;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    auto address = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto limit = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

    while (address < limit)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
            break;

        const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const auto size = static_cast<std::uintptr_t>(mbi.RegionSize);

        if (size == 0)
            break;   // defensive: a zero-size region would loop forever

        const bool usable = mbi.State == MEM_COMMIT &&
                            (mbi.Protect & k_readable) != 0 &&
                            (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;

        if (usable)
        {
            Region r;
            r.start      = base;
            r.end        = base + size;
            r.exec       = (mbi.Protect & k_executable) != 0;
            r.is_private = mbi.Type == MEM_PRIVATE;

            // Merge with the previous region when they are contiguous and share
            // the same attributes. Keeps the array small, which keeps the
            // binary search shallow.
            if (!m_regions.empty() &&
                m_regions.back().end == r.start &&
                m_regions.back().exec == r.exec &&
                m_regions.back().is_private == r.is_private)
            {
                m_regions.back().end = r.end;
            }
            else
            {
                m_regions.push_back(r);
            }

            m_total += size;
            if (r.is_private)
                m_private += size;
        }

        address = base + size;
    }
}

const RegionMap::Region* RegionMap::find(std::uintptr_t address) const
{
    // upper_bound gives the first region starting AFTER the address; the one
    // before it is the only candidate that can contain it.
    const auto it = std::upper_bound(m_regions.begin(), m_regions.end(), address,
                                     [](std::uintptr_t value, const Region& r)
                                     {
                                         return value < r.start;
                                     });

    if (it == m_regions.begin())
        return nullptr;

    const Region& candidate = *(it - 1);
    return (address >= candidate.start && address < candidate.end) ? &candidate : nullptr;
}

bool RegionMap::readable(std::uintptr_t address, std::size_t size) const
{
    if (address == 0 || size == 0)
        return false;

    const Region* r = find(address);
    if (r == nullptr)
        return false;

    return address + size <= r->end;
}

bool RegionMap::region_at(std::size_t index, std::uintptr_t& start, std::uintptr_t& end,
                          bool* is_private) const
{
    if (index >= m_regions.size())
        return false;

    start = m_regions[index].start;
    end   = m_regions[index].end;

    if (is_private != nullptr)
        *is_private = m_regions[index].is_private;

    return true;
}

bool RegionMap::executable(std::uintptr_t address) const
{
    const Region* r = find(address);
    return r != nullptr && r->exec;
}
}
