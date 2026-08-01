//
// Violet - entry point
//
// Stage 2: land inside GTA5_Enhanced.exe and come back with useful recon.
//
// We are still not touching the game's logic. The goal here is to answer four
// questions before we write a single hook:
//
//   1. Where is the game's code?      (base, .text bounds - stage 5 needs these)
//   2. What is the ASLR slide?        (the IDA <-> runtime conversion factor)
//   3. Is BattlEye actually off?      (it must be, for any of this to be sane)
//   4. Is anything already hooking Present? (stage 3's main hazard)
//
#include "core/log.hpp"
#include "core/process.hpp"
#include "render/overlay.hpp"

#include <Windows.h>

#include <cstdint>
#include <filesystem>
#include <string>

namespace
{
    HMODULE g_self = nullptr;

    // The base a 64-bit exe is normally linked to want. Not a rule, just the
    // overwhelmingly common default - we read the real value from the header
    // and only use this to sanity-check what we found.
    constexpr std::uintptr_t k_typical_exe_base = 0x140000000;

    void report_module_layout()
    {
        const auto info = violet::process::inspect(nullptr);
        if (!info)
        {
            VIOLET_ERROR("could not parse host PE headers - this should be impossible");
            return;
        }

        VIOLET_INFO("--- module layout -----------------------------------");
        VIOLET_INFO("  module          : {}", std::filesystem::path{ info->name }.string());
        VIOLET_INFO("  runtime base    : 0x{:X}", info->base);
        VIOLET_INFO("  preferred base  : 0x{:X}   (this is what IDA shows)", info->preferred_base);
        VIOLET_INFO("  size of image   : 0x{:X} ({:.1f} MB)",
                    info->size, static_cast<double>(info->size) / (1024.0 * 1024.0));

        // The one number that converts between IDA and reality.
        const std::intptr_t slide     = info->slide();
        const bool          negative  = slide < 0;
        const auto          magnitude = static_cast<std::uintmax_t>(negative ? -slide : slide);

        VIOLET_INFO("  relocation slide: {}0x{:X}", negative ? '-' : '+', magnitude);
        VIOLET_INFO("");
        VIOLET_INFO("  => runtime_address = ida_address {} 0x{:X}",
                    negative ? '-' : '+', magnitude);

        if (info->preferred_base != k_typical_exe_base)
            VIOLET_WARN("  preferred base is not the usual 0x{:X} - note this for IDA",
                        k_typical_exe_base);

        VIOLET_INFO("  mitigations     : {}", info->mitigations_string());

        VIOLET_INFO("");
        VIOLET_INFO("--- PE sections -------------------------------------");
        VIOLET_INFO("  {:<10} {:<16} {:<12} {:<14} {:>11}  {}",
                    "name", "runtime", "RVA", "IDA address", "size", "flags");

        for (const auto& s : info->sections)
        {
            // The RVA is the durable form: it survives ASLR, and it is what you
            // write down in notes. The IDA column is that same RVA rebased onto
            // the preferred base, so you can paste it straight into IDA's "jump
            // to address" box.
            const std::uintptr_t rva = s.start - info->base;
            VIOLET_INFO("  {:<10} 0x{:<14X} 0x{:<10X} 0x{:<12X} {:>11}  {}",
                        s.name, s.start, rva, info->preferred_base + rva,
                        s.size, s.flags_string());
        }

        VIOLET_INFO("");
        VIOLET_INFO("  {} sections total", info->sections.size());

        // Sections appearing AFTER .reloc, and duplicate section names, both
        // mean a tool rewrote this binary after the linker finished with it.
        // That is what anti-tamper and obfuscators do.
        std::size_t reloc_index = info->sections.size();
        for (std::size_t i = 0; i < info->sections.size(); ++i)
            if (info->sections[i].name == ".reloc")
                reloc_index = i;

        if (reloc_index + 1 < info->sections.size())
            VIOLET_WARN("  {} section(s) appear AFTER .reloc - binary was modified post-link",
                        info->sections.size() - reloc_index - 1);

        for (std::size_t i = 0; i < info->sections.size(); ++i)
            for (std::size_t j = i + 1; j < info->sections.size(); ++j)
                if (info->sections[i].name == info->sections[j].name)
                    VIOLET_WARN("  duplicate section name '{}' (#{} and #{})",
                                info->sections[i].name, i, j);

        // ---- the scan range -------------------------------------------------
        //
        // Deliberately NOT "the section called .text". This binary has two of
        // those, and searching only the first would silently miss a fifth of
        // the code with no error to tell you why your pattern wasn't found.
        VIOLET_INFO("");
        VIOLET_INFO("--- scan target: every executable section ------------");

        const auto code = info->executable_sections();
        for (const auto* s : code)
            VIOLET_INFO("  {:<10} 0x{:X} .. 0x{:X}   {:>11} bytes  ({:.1f} MB)",
                        s->name, s->start, s->start + s->size, s->size,
                        static_cast<double>(s->size) / (1024.0 * 1024.0));

        const std::size_t total = info->total_executable_bytes();
        VIOLET_INFO("  => {} section(s), {} bytes total ({:.1f} MB to scan)",
                    code.size(), total, static_cast<double>(total) / (1024.0 * 1024.0));
    }

    void report_loaded_modules()
    {
        const auto mods = violet::process::loaded_modules();

        VIOLET_INFO("");
        VIOLET_INFO("--- loaded modules ({}) ------------------------------", mods.size());

        bool any_flagged = false;
        bool anti_cheat  = false;

        for (const auto& m : mods)
        {
            const auto flag = violet::process::classify(m.name);
            if (flag == violet::process::ModuleFlag::Normal)
                continue;

            any_flagged = true;
            if (flag == violet::process::ModuleFlag::AntiCheat)
                anti_cheat = true;

            VIOLET_INFO("  [{:<12}] {:<36} @ 0x{:X}",
                        violet::process::to_string(flag),
                        std::filesystem::path{ m.name }.string(), m.base);
        }

        if (!any_flagged)
            VIOLET_INFO("  (nothing noteworthy)");

        if (anti_cheat)
        {
            VIOLET_ERROR("");
            VIOLET_ERROR("  ****************************************************");
            VIOLET_ERROR("  ANTI-CHEAT IS LOADED IN THIS PROCESS.");
            VIOLET_ERROR("  Stop here. Relaunch with BattlEye disabled before");
            VIOLET_ERROR("  going any further.");
            VIOLET_ERROR("  ****************************************************");
        }
    }

    void report_environment()
    {
        VIOLET_INFO("");
        VIOLET_INFO("--- environment -------------------------------------");

        // If this is true while we are just injecting normally, something else
        // is attached - usually x64dbg, which is fine and often intentional.
        VIOLET_INFO("  debugger attached : {}", IsDebuggerPresent() ? "yes" : "no");

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        VIOLET_INFO("  logical cores     : {}", si.dwNumberOfProcessors);
        VIOLET_INFO("  page size         : {} bytes", si.dwPageSize);
    }

    DWORD WINAPI violet_main(LPVOID)
    {
        violet::log::init(g_self, /*also_open_console=*/ true);

        VIOLET_INFO("========================================");
        VIOLET_INFO(" Violet v0.1.0  -  stage 2: recon");
        VIOLET_INFO("========================================");

        wchar_t host_path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, host_path, MAX_PATH);

        VIOLET_INFO("host process : {}", std::filesystem::path{ host_path }.filename().string());
        VIOLET_INFO("host pid     : {}", GetCurrentProcessId());
        VIOLET_INFO("");

        report_module_layout();
        report_loaded_modules();
        report_environment();

        VIOLET_INFO("");
        VIOLET_INFO("recon complete - starting overlay");
        VIOLET_INFO("");

        // Blocks until the user presses END. Owns the window, the D3D12 device
        // and the render loop, and cleans all of it up before returning.
        violet::render::run_overlay(g_self);

        VIOLET_INFO("overlay returned - unloading");
        violet::log::shutdown();

        // NOTE for stage 3 onwards: once we install a DX12 Present hook, this
        // becomes dangerous. Unloading the DLL while the game's render thread
        // is executing inside our hook leaves it returning into freed memory.
        // We will need to uninstall hooks and wait for the render thread to
        // leave them before we get here.
        FreeLibraryAndExitThread(g_self, 0);
    }
}

BOOL APIENTRY DllMain(HMODULE self, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = self;

        // ---- The single most important rule of DLL injection ----
        //
        // DllMain runs while the Windows loader still holds a process-wide lock
        // (the "loader lock"). Doing real work here - opening files, creating
        // windows, calling into other DLLs, waiting on anything - can deadlock
        // the entire process instantly, and the hang will look like a random
        // freeze with no stack trace.
        //
        // The rule is: get in, spawn a thread, get out.
        //
        // DisableThreadLibraryCalls is a small optimisation: it stops Windows
        // calling us back for every thread the game creates and destroys, and
        // GTA creates a lot of threads.
        DisableThreadLibraryCalls(self);

        if (const HANDLE t = CreateThread(nullptr, 0, violet_main, nullptr, 0, nullptr))
            CloseHandle(t);   // we don't need the handle; closing it doesn't stop the thread
    }

    return TRUE;
}
