#include "core/log.hpp"

#include <Windows.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <system_error>

namespace violet::log
{
namespace
{
    std::ofstream g_file;
    bool          g_console = false;

    // GTA is aggressively multithreaded, and soon Violet will be too (our main
    // thread, plus the game's render thread calling into our DX12 hook). Two
    // threads writing at once without this lock produces interleaved garbage.
    std::mutex g_mutex;

    std::string timestamp()
    {
        // Deliberately using the plain Win32 call rather than std::chrono's
        // time zone machinery - it has zero setup cost and cannot fail.
        SYSTEMTIME t{};
        GetLocalTime(&t);
        return std::format("{:02}:{:02}:{:02}.{:03}",
                           t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    }
}

void init(void* self, bool also_open_console, const wchar_t* filename)
{
    // The log goes to a fixed location: %LOCALAPPDATA%\Violet\Violet.log
    //
    // It used to sit next to the DLL, which was tidy right up until the
    // injector started loading a disposable COPY from a staging folder (so that
    // building Violet does not fail while Violet is loaded). "Next to the DLL"
    // now means a temp directory nobody would think to look in.
    //
    // A fixed path is better anyway: it never lands in the game's install
    // folder, and never in a synced folder where a sync client would fight the
    // flush-on-every-line below.
    std::filesystem::path log_path;

    wchar_t*    local_app_data = nullptr;
    std::size_t length         = 0;

    if (_wdupenv_s(&local_app_data, &length, L"LOCALAPPDATA") == 0 && local_app_data != nullptr)
    {
        log_path = std::filesystem::path{ local_app_data } / L"Violet";
        std::free(local_app_data);

        std::error_code ec;
        std::filesystem::create_directories(log_path, ec);
        log_path /= filename;
    }
    else
    {
        // Fall back to sitting beside whatever module we were loaded from.
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(static_cast<HMODULE>(self), path, MAX_PATH);
        log_path = path;
        log_path.replace_filename(filename);
    }

    // trunc = start fresh each launch. You want the current run's log, not a
    // 400 MB file with fifty runs concatenated together.
    g_file.open(log_path, std::ios::out | std::ios::trunc);

    if (also_open_console)
    {
        // A real console window is enormously easier to watch than tailing a
        // file, especially while the game is running. We will turn this off
        // later; for now it is our main feedback channel.
        if (AllocConsole())
        {
            SetConsoleTitleW(L"Violet - debug console");

            // AllocConsole gives the process a console, but our C runtime's
            // stdout still points at nothing. This re-points it at the new
            // console so printf actually appears.
            FILE* dummy = nullptr;
            freopen_s(&dummy, "CONOUT$", "w", stdout);
            g_console = true;
        }
    }

    write_line("INFO", "logger online");
    write_line("INFO", std::format("log file: {}", log_path.string()));
}

void write_line(std::string_view level, std::string_view msg)
{
    const std::scoped_lock lock{ g_mutex };

    const std::string line = std::format("[{}] [{:<5}] {}", timestamp(), level, msg);

    if (g_file.is_open())
    {
        g_file << line << '\n';

        // Flushing on every single line is slow - and completely worth it. When
        // the game crashes, anything still sitting in the buffer is lost, and
        // the line you lose is always the one that would have told you why.
        g_file.flush();
    }

    if (g_console)
        std::printf("%s\n", line.c_str());

    // Bonus channel: this shows up in x64dbg's log and in Sysinternals
    // DebugView, so you can read Violet's output even with no console at all.
    OutputDebugStringA((line + "\n").c_str());
}

void shutdown()
{
    // Logged before taking the lock - write_line locks internally, and locking
    // a std::mutex twice on the same thread is an instant deadlock.
    write_line("INFO", "logger shutting down");

    const std::scoped_lock lock{ g_mutex };

    if (g_file.is_open())
        g_file.close();

    if (g_console)
    {
        FreeConsole();
        g_console = false;
    }
}
}
