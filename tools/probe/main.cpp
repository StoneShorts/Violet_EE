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
        VIOLET_INFO("");
        violet::game::crack_chain(0x3ED4C20);

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
