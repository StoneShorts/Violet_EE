#pragma once
//
// Violet - logging
//
// Why this is the very first thing we build:
//
// Once our code is running inside GTA there is no stdout, no debugger attached,
// and no way to see what happened. If the game hard-crashes, the last line in
// this file is your only clue about where it died. This is the black box
// recorder, and for the next several weeks you will diagnose almost every bug
// by reading it.
//
// Usage:
//     VIOLET_INFO("player ped handle = {}", handle);
//     VIOLET_ERROR("pattern not found: {}", name);
//
#include <format>
#include <string_view>

namespace violet::log
{
    // Call once, as early as possible.
    //
    // `self` is our own module handle (the HMODULE that DllMain hands us). We
    // use it to work out where Violet.dll lives on disk, so the log file lands
    // next to the DLL instead of in whatever the host process happens to have
    // set as its current working directory.
    // `filename` lets a second, separately-injected component (the probe tool)
    // write its own log rather than truncating the running menu's.
    void init(void* self, bool also_open_console, const wchar_t* filename = L"Violet.log");

    void shutdown();

    // The one function that actually touches the file. Everything else is sugar
    // that eventually calls this.
    void write_line(std::string_view level, std::string_view msg);
}

// These are macros rather than functions purely so that std::format's compile-
// time format-string checking works correctly at the call site.
#define VIOLET_INFO(...)  ::violet::log::write_line("INFO",  ::std::format(__VA_ARGS__))
#define VIOLET_WARN(...)  ::violet::log::write_line("WARN",  ::std::format(__VA_ARGS__))
#define VIOLET_ERROR(...) ::violet::log::write_line("ERROR", ::std::format(__VA_ARGS__))
