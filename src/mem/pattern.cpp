#include "mem/pattern.hpp"

#include "core/log.hpp"
#include "core/process.hpp"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <format>

namespace violet::mem
{
namespace
{
    double      g_last_ms    = 0.0;
    std::size_t g_last_bytes = 0;

    int hex_value(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    bool matches_at(const std::uint8_t* at, const Pattern& p)
    {
        const std::uint8_t* bytes = p.bytes();
        const char*         mask  = p.mask();

        for (std::size_t i = 0, n = p.size(); i < n; ++i)
            if (mask[i] && at[i] != bytes[i])
                return false;

        return true;
    }

    // Search one contiguous region.
    const std::uint8_t* find_in(const std::uint8_t* begin, std::size_t size, const Pattern& p)
    {
        const std::size_t n = p.size();
        if (n == 0 || size < n)
            return nullptr;

        const std::uint8_t* const limit = begin + (size - n);   // last valid start

        const std::size_t  anchor      = p.anchor();
        const std::uint8_t anchor_byte = p.bytes()[anchor];
        const bool         use_anchor  = p.has_anchor();

        const std::uint8_t* cur = begin;

        while (cur <= limit)
        {
            if (use_anchor)
            {
                // memchr is vectorised in the CRT and skips enormous stretches
                // of non-matching bytes far faster than a byte-at-a-time loop.
                // We search for the anchor byte across every candidate start
                // position that is still in range.
                const std::size_t span = static_cast<std::size_t>(limit - cur) + 1;
                const void* hit = std::memchr(cur + anchor, anchor_byte, span);
                if (hit == nullptr)
                    return nullptr;

                cur = static_cast<const std::uint8_t*>(hit) - anchor;
                if (cur > limit)
                    return nullptr;
            }

            if (matches_at(cur, p))
                return cur;

            ++cur;
        }

        return nullptr;
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
}

// ---------------------------------------------------------------------------
// Pattern
// ---------------------------------------------------------------------------

std::optional<Pattern> Pattern::parse(std::string_view signature)
{
    Pattern p;
    p.m_text.assign(signature);

    std::size_t i = 0;
    while (i < signature.size())
    {
        const char c = signature[i];

        if (std::isspace(static_cast<unsigned char>(c)))
        {
            ++i;
            continue;
        }

        if (c == '?')
        {
            p.m_bytes.push_back(0);
            p.m_mask.push_back(0);
            ++i;
            if (i < signature.size() && signature[i] == '?')   // accept "??" too
                ++i;
            continue;
        }

        if (i + 1 >= signature.size())
            return std::nullopt;

        const int hi = hex_value(signature[i]);
        const int lo = hex_value(signature[i + 1]);
        if (hi < 0 || lo < 0)
            return std::nullopt;

        p.m_bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
        p.m_mask.push_back(1);
        i += 2;
    }

    if (p.m_bytes.empty())
        return std::nullopt;

    for (std::size_t k = 0; k < p.m_mask.size(); ++k)
    {
        if (p.m_mask[k])
        {
            p.m_anchor     = k;
            p.m_has_anchor = true;
            break;
        }
    }

    return p;
}

std::size_t Pattern::fixed_count() const
{
    return static_cast<std::size_t>(std::count(m_mask.begin(), m_mask.end(), 1));
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

std::uintptr_t ScanResult::rip(int displacement_offset, int instruction_length) const
{
    if (address == 0)
        return 0;
    return resolve_rip(address, displacement_offset, instruction_length);
}

std::uintptr_t ScanResult::rva() const
{
    const auto info = violet::process::inspect(nullptr);
    if (!info || address == 0)
        return 0;
    return address - info->base;
}

std::uintptr_t ScanResult::ida() const
{
    const auto info = violet::process::inspect(nullptr);
    if (!info || address == 0)
        return 0;
    return info->preferred_base + (address - info->base);
}

// ---------------------------------------------------------------------------
// scanning
// ---------------------------------------------------------------------------

std::uintptr_t resolve_rip(std::uintptr_t instruction,
                           int displacement_offset,
                           int instruction_length)
{
    if (instruction == 0)
        return 0;

    // The displacement is a SIGNED 32-bit value - globals frequently live at
    // lower addresses than the code referencing them, so negatives are normal.
    // Reading it as unsigned is a classic way to end up ~4 GB off target.
    const auto displacement = *reinterpret_cast<const std::int32_t*>(
        instruction + static_cast<std::uintptr_t>(displacement_offset));

    // Relative to the NEXT instruction, not to the displacement field.
    return instruction + static_cast<std::uintptr_t>(instruction_length)
                       + static_cast<std::intptr_t>(displacement);
}

std::vector<std::uintptr_t> scan_all(const Pattern& p, std::size_t limit)
{
    std::vector<std::uintptr_t> out;

    const auto info = violet::process::inspect(nullptr);
    if (!info)
        return out;

    const Timer timer;
    std::size_t scanned = 0;

    // Every executable section, not "the one called .text". GTA5_Enhanced.exe
    // has two of those, and searching only the first silently misses a fifth
    // of the binary.
    for (const auto* section : info->executable_sections())
    {
        const auto* begin = reinterpret_cast<const std::uint8_t*>(section->start);
        std::size_t remaining = section->size;
        const std::uint8_t* cursor = begin;

        scanned += section->size;

        while (remaining >= p.size())
        {
            const std::uint8_t* hit = find_in(cursor, remaining, p);
            if (hit == nullptr)
                break;

            out.push_back(reinterpret_cast<std::uintptr_t>(hit));
            if (out.size() >= limit)
            {
                g_last_ms    = timer.ms();
                g_last_bytes = scanned;
                return out;
            }

            const std::size_t consumed = static_cast<std::size_t>(hit - cursor) + 1;
            cursor    += consumed;
            remaining -= consumed;
        }
    }

    g_last_ms    = timer.ms();
    g_last_bytes = scanned;
    return out;
}

ScanResult scan(const Pattern& p)
{
    const auto info = violet::process::inspect(nullptr);
    if (!info)
        return {};

    const Timer timer;
    std::size_t scanned = 0;

    for (const auto* section : info->executable_sections())
    {
        scanned += section->size;

        const auto* begin = reinterpret_cast<const std::uint8_t*>(section->start);
        if (const std::uint8_t* hit = find_in(begin, section->size, p))
        {
            g_last_ms    = timer.ms();
            g_last_bytes = scanned;
            return ScanResult{ reinterpret_cast<std::uintptr_t>(hit) };
        }
    }

    g_last_ms    = timer.ms();
    g_last_bytes = scanned;
    return {};
}

ScanResult scan(std::string_view signature)
{
    const auto p = Pattern::parse(signature);
    if (!p)
    {
        VIOLET_ERROR("malformed signature: '{}'", signature);
        return {};
    }
    return scan(*p);
}

double      last_scan_ms()    { return g_last_ms; }
std::size_t last_scan_bytes() { return g_last_bytes; }

// ---------------------------------------------------------------------------
// self_test
// ---------------------------------------------------------------------------

SelfTest self_test()
{
    SelfTest result;

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

    // Work in the largest code section, well away from its edges.
    const auto* biggest = *std::max_element(code.begin(), code.end(),
        [](const auto* a, const auto* b) { return a->size < b->size; });

    constexpr std::size_t k_sample_len = 24;

    // Find a sample with enough variety in it. Code sections contain long runs
    // of padding (0xCC int3 filler between functions), and a signature made of
    // twenty identical bytes would match thousands of places and prove nothing.
    std::uintptr_t sample_at = 0;
    for (std::size_t step = 0; step < 64; ++step)
    {
        const std::uintptr_t candidate = biggest->start + biggest->size / 2
                                       + step * k_sample_len;

        if (candidate + k_sample_len >= biggest->start + biggest->size)
            break;

        const auto* bytes = reinterpret_cast<const std::uint8_t*>(candidate);

        std::size_t distinct = 0;
        bool seen[256]{};
        for (std::size_t i = 0; i < k_sample_len; ++i)
        {
            if (!seen[bytes[i]]) { seen[bytes[i]] = true; ++distinct; }
        }

        if (distinct >= 8)
        {
            sample_at = candidate;
            break;
        }
    }

    if (sample_at == 0)
    {
        result.detail = "could not find a varied enough sample of code";
        return result;
    }

    // Build an IDA-style signature from those bytes, wildcarding four in the
    // middle so the wildcard path is genuinely exercised.
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(sample_at);

    std::string signature;
    for (std::size_t i = 0; i < k_sample_len; ++i)
    {
        if (i != 0)
            signature += ' ';

        if (i >= 10 && i < 14)
        {
            signature += '?';
        }
        else
        {
            static const char* digits = "0123456789ABCDEF";
            signature += digits[bytes[i] >> 4];
            signature += digits[bytes[i] & 0x0F];
        }
    }

    const auto pattern = Pattern::parse(signature);
    if (!pattern)
    {
        result.detail = "parser rejected a signature it generated itself";
        return result;
    }

    if (pattern->size() != k_sample_len)
    {
        result.detail = std::format("parsed {} bytes, expected {}",
                                    pattern->size(), k_sample_len);
        return result;
    }

    const auto hits = scan_all(*pattern);

    result.matches       = hits.size();
    result.elapsed_ms    = last_scan_ms();
    result.bytes_scanned = last_scan_bytes();

    // The real assertion: the address we took the bytes FROM must be among the
    // matches. Anything else means the scanner is walking memory incorrectly.
    if (std::find(hits.begin(), hits.end(), sample_at) == hits.end())
    {
        result.detail = std::format(
            "sampled 0x{:X} but the scan did not return it ({} other matches)",
            sample_at, hits.size());
        return result;
    }

    result.passed = true;
    result.detail = std::format("found 0x{:X} (+{} other match{})",
                                sample_at, hits.size() - 1,
                                hits.size() == 2 ? "" : "es");
    return result;
}
}
