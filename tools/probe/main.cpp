//
// probe.dll - run an analysis pass inside the game and leave again
//
// This exists so investigation does not require the whole menu.
//
// Violet may already be injected and running its overlay; injecting a second
// copy would give you two windows fighting over the same hotkeys and two
// writers truncating the same log. The probe instead carries only the analysis
// code: no window, no D3D12, no ImGui, no hotkeys. It runs one pass, writes its
// findings to its own log file, and unloads itself.
//
// That makes it safe to fire at a live session repeatedly while iterating on
// what we are looking for.
//
#include "core/log.hpp"
#include "core/process.hpp"
#include "game/native_table.hpp"

#include <Windows.h>

#include <filesystem>

namespace
{
    HMODULE g_self = nullptr;

    DWORD WINAPI probe_main(LPVOID)
    {
        // Its own log, and deliberately no console - popping one over someone's
        // running game is rude.
        violet::log::init(g_self, /*also_open_console=*/ false, L"Violet_probe.log");

        VIOLET_INFO("========================================");
        VIOLET_INFO(" Violet probe - native table hunt");
        VIOLET_INFO("========================================");

        wchar_t host[MAX_PATH]{};
        GetModuleFileNameW(nullptr, host, MAX_PATH);
        VIOLET_INFO("host : {}", std::filesystem::path{ host }.filename().string());
        VIOLET_INFO("pid  : {}", GetCurrentProcessId());

        if (const auto info = violet::process::inspect(nullptr))
        {
            VIOLET_INFO("base : 0x{:X}   preferred 0x{:X}", info->base, info->preferred_base);
            VIOLET_INFO("");
        }

        const auto scan = violet::game::find_native_table();

        VIOLET_INFO("--- result -----------------------------------------");
        VIOLET_INFO("  took      : {:.0f} ms", scan.elapsed_ms);
        VIOLET_INFO("  found     : {}", scan.found ? "YES" : "no");
        VIOLET_INFO("  detail    : {}", scan.detail);

        if (scan.table != 0)
        {
            VIOLET_INFO("  table     : 0x{:X}", scan.table);
            VIOLET_INFO("  table RVA : 0x{:X}   (IDA 0x{:X})",
                        scan.table_rva, 0x140000000ull + scan.table_rva);
            VIOLET_INFO("  slots     : {} of 256", scan.slots);
            VIOLET_INFO("  blocks    : {}", scan.blocks);
            VIOLET_INFO("  natives   : {}", scan.natives);

            for (const auto& s : scan.samples)
                VIOLET_INFO("    hash 0x{:016X}  ->  handler 0x{:X}", s.hash, s.handler);
        }

        // Hashes are not stored in plaintext (established by hunt_known_hashes
        // on an earlier run - the only matches were the probe's own constants).
        // So the table has to be found structurally.
        // The real decode, using the layout read out of GTA's own
        // registerNative(). Located automatically rather than hardcoded.
        VIOLET_INFO("");
        VIOLET_INFO("--- decoding the native table ----------------------");
        {
            const auto decoded = violet::game::decode_native_table();

            VIOLET_INFO("  took      : {:.0f} ms", decoded.elapsed_ms);
            VIOLET_INFO("  result    : {}", decoded.ok ? "SUCCESS" : "failed");
            VIOLET_INFO("  detail    : {}", decoded.detail);

            if (decoded.table != 0)
            {
                VIOLET_INFO("  table     : 0x{:X}", decoded.table);
                VIOLET_INFO("  table RVA : 0x{:X}   (IDA 0x{:X})",
                            decoded.table_rva, 0x140000000ull + decoded.table_rva);
            }

            // ---- self-verification against the static disassembly ----
            //
            // These pairs were read out of sub_140922F20 in the memory dump,
            // where the game registers natives with literal hashes:
            //
            //     lea  r8,  qword_140920EA0
            //     mov  rdx, 4EDE34FBADD967A6h
            //     call sub_140920D70
            //
            // If the live decode resolves each hash to the same RVA the static
            // disassembly assigns it, the decode is correct - independently
            // confirmed by two entirely separate methods.
            struct Check { std::uint64_t hash; std::uintptr_t expect_rva; };
            constexpr Check checks[] = {
                { 0x4EDE34FBADD967A6ull, 0x920EA0 },
                { 0xE81651AD79516E48ull, 0x921080 },
                { 0xB8BA7F44DF1575E1ull, 0x921290 },
                { 0xEB1C67C3A5333A92ull, 0x9214B0 },
                { 0xC4BB298BD441BE78ull, 0x9216D0 },
            };

            const auto module_info = violet::process::inspect(nullptr);
            const std::uintptr_t base = module_info ? module_info->base : 0;

            VIOLET_INFO("");
            VIOLET_INFO("  cross-check against the static disassembly:");

            int matched = 0;
            for (const auto& c : checks)
            {
                const auto handler = violet::game::find_native_handler(c.hash);
                const auto rva = (handler && base) ? handler - base : 0;
                const bool ok = rva == c.expect_rva;
                matched += ok ? 1 : 0;

                VIOLET_INFO("    0x{:016X} -> RVA 0x{:<8X} expected 0x{:<8X}  {}",
                            c.hash, rva, c.expect_rva, ok ? "MATCH" : "mismatch");
            }

            VIOLET_INFO("");
            if (matched == static_cast<int>(std::size(checks)))
                VIOLET_INFO("  *** {}/{} match - the decode is CORRECT ***",
                            matched, std::size(checks));
            else
                VIOLET_WARN("  only {}/{} matched", matched, std::size(checks));

            // Sample the decoded set, so the log shows real data rather than
            // just a count.
            const auto& all = violet::game::decoded_natives();
            VIOLET_INFO("");
            VIOLET_INFO("  first 8 of {} decoded natives:", all.size());
            for (std::size_t i = 0; i < all.size() && i < 8; ++i)
                VIOLET_INFO("    0x{:016X} -> RVA 0x{:X}",
                            all[i].hash, base ? all[i].handler - base : 0);
        }

        VIOLET_INFO("");
        VIOLET_INFO("probe complete - unloading");
        violet::log::shutdown();

        FreeLibraryAndExitThread(g_self, 0);
    }
}

BOOL APIENTRY DllMain(HMODULE self, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = self;
        DisableThreadLibraryCalls(self);

        if (const HANDLE t = CreateThread(nullptr, 0, probe_main, nullptr, 0, nullptr))
            CloseHandle(t);
    }
    return TRUE;
}
