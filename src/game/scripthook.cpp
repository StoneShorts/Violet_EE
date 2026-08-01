#include "game/scripthook.hpp"

#include "core/log.hpp"
#include "game/features.hpp"

#include <Windows.h>

#include <atomic>
#include <format>
#include <string_view>

namespace violet::game
{
namespace
{
    using ScriptRegisterFn   = void (*)(HMODULE, void (*)());
    using ScriptUnregisterFn = void (*)(HMODULE);
    using ScriptWaitFn       = void (*)(DWORD);
    using NativeInitFn       = void (*)(std::uint64_t);
    using NativePushFn       = void (*)(std::uint64_t);
    using NativeCallFn       = std::uint64_t* (*)();

    HMODULE            g_dll = nullptr;
    ScriptRegisterFn   g_script_register   = nullptr;
    ScriptUnregisterFn g_script_unregister = nullptr;
    ScriptWaitFn       g_script_wait       = nullptr;
    NativeInitFn       g_native_init       = nullptr;
    NativePushFn       g_native_push       = nullptr;
    NativeCallFn       g_native_call       = nullptr;

    bool        g_bound = false;
    std::string g_status = "not looked for yet";

    std::atomic<bool>          g_thread_alive{ false };
    std::atomic<std::uint64_t> g_ticks{ 0 };

    // Walk a module's export table looking for a symbol whose (mangled) name
    // contains `fragment`.
    //
    // ScriptHookV exports C++ symbols, so the real names look like
    // "?nativeInit@@YAX_K@Z". Hardcoding those would break the moment a
    // signature changed; matching on the readable fragment inside them will
    // not, and it lets us log precisely what we found.
    FARPROC find_export(HMODULE module, std::string_view fragment)
    {
        const auto base = reinterpret_cast<const std::uint8_t*>(module);

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0)
            return nullptr;

        const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            base + dir.VirtualAddress);

        const auto* names    = reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
        const auto* ordinals = reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
        const auto* functions= reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);

        for (DWORD i = 0; i < exports->NumberOfNames; ++i)
        {
            const std::string_view name{ reinterpret_cast<const char*>(base + names[i]) };

            if (name.find(fragment) != std::string_view::npos)
                return reinterpret_cast<FARPROC>(
                    const_cast<std::uint8_t*>(base + functions[ordinals[i]]));
        }

        return nullptr;
    }

    // Called by ScriptHookV, on the game's script thread. This is the only
    // place in Violet where a native may legally be invoked.
    void script_main()
    {
        g_thread_alive = true;
        VIOLET_INFO("script thread is live - natives are now callable");

        while (true)
        {
            g_ticks.fetch_add(1, std::memory_order_relaxed);

            // Everything the menu wants done happens here. The UI thread only
            // ever sets flags; this thread is the one holding the engine's hand.
            violet::game::features_tick();

            if (g_script_wait != nullptr)
                g_script_wait(0);   // yield until the next game frame
            else
                Sleep(1);
        }
    }
}

bool bind_scripthook()
{
    if (g_bound)
        return true;

    // Already loaded by the ASI loader if the user installed it properly. We
    // deliberately do NOT LoadLibrary it ourselves: ScriptHookV expects to be
    // initialised by the game's own startup, and loading it late from an
    // injected thread is not a supported path.
    g_dll = GetModuleHandleW(L"ScriptHookV.dll");
    if (g_dll == nullptr)
    {
        g_status = "ScriptHookV.dll is not loaded in this process";
        return false;
    }

    struct Binding { const char* fragment; FARPROC* out; const char* label; };

    const Binding bindings[] = {
        { "scriptRegister",   reinterpret_cast<FARPROC*>(&g_script_register),   "scriptRegister"   },
        { "scriptUnregister", reinterpret_cast<FARPROC*>(&g_script_unregister), "scriptUnregister" },
        { "scriptWait",       reinterpret_cast<FARPROC*>(&g_script_wait),       "scriptWait"       },
        { "nativeInit",       reinterpret_cast<FARPROC*>(&g_native_init),       "nativeInit"       },
        { "nativePush64",     reinterpret_cast<FARPROC*>(&g_native_push),       "nativePush64"     },
        { "nativeCall",       reinterpret_cast<FARPROC*>(&g_native_call),       "nativeCall"       },
    };

    VIOLET_INFO("ScriptHookV.dll found at 0x{:X}, resolving exports:",
                reinterpret_cast<std::uintptr_t>(g_dll));

    bool all_found = true;
    for (const auto& b : bindings)
    {
        *b.out = find_export(g_dll, b.fragment);
        VIOLET_INFO("  {:<18} {}", b.label, *b.out ? "ok" : "MISSING");

        // scriptUnregister missing is survivable; the rest are not.
        if (*b.out == nullptr && b.out != reinterpret_cast<FARPROC*>(&g_script_unregister))
            all_found = false;
    }

    if (!all_found)
    {
        g_status = "ScriptHookV.dll is loaded but its exports did not resolve";
        return false;
    }

    g_bound  = true;
    g_status = "ready";
    return true;
}

bool scripthook_available()          { return g_bound; }
const std::string& scripthook_status() { return g_status; }

void start_script_thread(void* self_module)
{
    if (!g_bound || g_script_register == nullptr)
        return;

    g_script_register(static_cast<HMODULE>(self_module), script_main);
    VIOLET_INFO("registered script thread with ScriptHookV");
}

void stop_script_thread(void* self_module)
{
    if (g_script_unregister != nullptr)
        g_script_unregister(static_cast<HMODULE>(self_module));

    g_thread_alive = false;
}

bool script_thread_alive()        { return g_thread_alive.load(); }
std::uint64_t script_tick_count() { return g_ticks.load(std::memory_order_relaxed); }

void native_init(std::uint64_t hash)   { if (g_native_init) g_native_init(hash); }
void native_push(std::uint64_t value)  { if (g_native_push) g_native_push(value); }

std::uint64_t* native_call()
{
    return g_native_call ? g_native_call() : nullptr;
}
}
