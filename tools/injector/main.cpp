//
// inject.exe - Violet's DLL injector
//
// Usage:   inject.exe <process.exe> <path\to\Violet.dll>
// Example: inject.exe GTA5_Enhanced.exe bin\Violet.dll
//
// ---------------------------------------------------------------------------
// How injection actually works
// ---------------------------------------------------------------------------
//
// Our goal is to make ANOTHER process call LoadLibraryW("...\Violet.dll").
// Once it does, Windows' own loader maps our DLL in and calls our DllMain, and
// from that moment our code is running inside the game with full access to its
// memory.
//
// Four steps:
//
//   1. Find the target process by name and open a handle with enough rights.
//   2. VirtualAllocEx  - allocate a small buffer inside ITS address space.
//   3. WriteProcessMemory - copy our DLL path string into that buffer.
//   4. CreateRemoteThread - start a thread in the target whose entry point is
//      LoadLibraryW, with our buffer as its argument.
//
// Step 4 relies on two happy accidents:
//
//   * kernel32.dll is loaded at the same base address in every process for a
//     given boot, so LoadLibraryW's address in OUR process is also its address
//     in THEIRS. We can look it up locally and use it remotely.
//
//   * A thread entry point has the shape  DWORD f(LPVOID), and LoadLibraryW has
//     the shape  HMODULE f(LPCWSTR). One pointer in, one pointer-sized value
//     out. On x64 those are calling-convention compatible, so we can hand
//     LoadLibraryW straight to CreateRemoteThread as if it were a thread proc.
//
// This is the classic technique. It is easy to detect, which does not matter at
// all for single-player, and it is the right thing to learn first because every
// fancier method (manual mapping, thread hijacking, APC injection) is a
// variation on the same four steps.
//
#include <Windows.h>
#include <TlHelp32.h>

#include <filesystem>
#include <iostream>
#include <string>

namespace
{
    // Walk the system process list looking for a matching executable name.
    DWORD find_pid(const std::wstring& exe_name)
    {
        // A "snapshot" is a frozen copy of the process list at this instant.
        const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);   // required, or Process32FirstW fails

        DWORD pid = 0;
        if (Process32FirstW(snap, &entry))
        {
            do
            {
                if (_wcsicmp(entry.szExeFile, exe_name.c_str()) == 0)
                {
                    pid = entry.th32ProcessID;
                    break;
                }
            }
            while (Process32NextW(snap, &entry));
        }

        CloseHandle(snap);
        return pid;
    }

    void print_last_error(const char* what)
    {
        const DWORD code = GetLastError();
        std::wcerr << L"[!] " << what << L" failed (GetLastError = " << code << L")\n";

        if (code == ERROR_ACCESS_DENIED)
            std::wcerr << L"    ERROR_ACCESS_DENIED - try running inject.exe as Administrator.\n";
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3)
    {
        std::wcout << L"Violet injector\n\n"
                      L"  usage: inject.exe <process.exe> <path\\to\\dll>\n"
                      L"  e.g.:  inject.exe GTA5_Enhanced.exe bin\\Violet.dll\n";
        return 1;
    }

    const std::wstring target = argv[1];

    // Resolve to an absolute path. The remote process has a different working
    // directory than we do, so a relative path would mean something else - or
    // nothing at all - once it gets there.
    std::filesystem::path dll;
    try
    {
        dll = std::filesystem::absolute(argv[2]);
    }
    catch (const std::exception& e)
    {
        std::wcerr << L"[!] bad dll path: " << e.what() << L"\n";
        return 1;
    }

    if (!std::filesystem::exists(dll))
    {
        std::wcerr << L"[!] dll not found: " << dll.wstring() << L"\n";
        return 1;
    }

    std::wcout << L"[*] dll    : " << dll.wstring() << L"\n";
    std::wcout << L"[*] target : " << target << L"\n";

    // ---- 1. find and open the target ------------------------------------
    const DWORD pid = find_pid(target);
    if (pid == 0)
    {
        std::wcerr << L"[!] process not running: " << target << L"\n";
        return 1;
    }
    std::wcout << L"[*] pid    : " << pid << L"\n";

    // Ask for exactly the rights the four steps need, and no more.
    const HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD |      // step 4
        PROCESS_VM_OPERATION  |      // step 2 (VirtualAllocEx)
        PROCESS_VM_WRITE      |      // step 3
        PROCESS_VM_READ       |
        PROCESS_QUERY_INFORMATION,
        FALSE, pid);

    if (proc == nullptr)
    {
        print_last_error("OpenProcess");
        return 1;
    }

    int result = 1;
    LPVOID remote_path = nullptr;

    do
    {
        // ---- 2. allocate a buffer inside the target -----------------------
        const std::wstring path_str = dll.wstring();
        const SIZE_T bytes = (path_str.size() + 1) * sizeof(wchar_t);   // +1 for the null terminator

        remote_path = VirtualAllocEx(proc, nullptr, bytes,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remote_path == nullptr)
        {
            print_last_error("VirtualAllocEx");
            break;
        }
        std::wcout << L"[*] remote buffer @ 0x" << std::hex << remote_path << std::dec << L"\n";

        // ---- 3. write the path into it ------------------------------------
        if (!WriteProcessMemory(proc, remote_path, path_str.c_str(), bytes, nullptr))
        {
            print_last_error("WriteProcessMemory");
            break;
        }

        // ---- 4. make the target call LoadLibraryW(remote_path) ------------
        const auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));

        if (load_library == nullptr)
        {
            print_last_error("GetProcAddress(LoadLibraryW)");
            break;
        }

        const HANDLE thread = CreateRemoteThread(proc, nullptr, 0,
                                                 load_library, remote_path, 0, nullptr);
        if (thread == nullptr)
        {
            print_last_error("CreateRemoteThread");
            break;
        }

        std::wcout << L"[*] remote thread started, waiting...\n";
        WaitForSingleObject(thread, 10'000);

        // The thread's exit code is whatever LoadLibraryW returned - the HMODULE
        // of our newly loaded DLL - truncated to 32 bits by the thread-exit-code
        // API. Truncated or not, zero still unambiguously means failure.
        DWORD exit_code = 0;
        GetExitCodeThread(thread, &exit_code);
        CloseHandle(thread);

        if (exit_code == 0)
        {
            std::wcerr << L"[!] LoadLibraryW returned NULL inside the target.\n"
                          L"    Usual causes: the DLL is 32-bit (must be x64), or one of\n"
                          L"    its dependencies is missing from the target's search path.\n";
            break;
        }

        std::wcout << L"[+] injected. remote HMODULE (low 32 bits) = 0x"
                   << std::hex << exit_code << std::dec << L"\n";
        result = 0;
    }
    while (false);

    // Clean up the buffer. LoadLibraryW has already copied the string it needed,
    // so the memory is safe to release even on success.
    if (remote_path != nullptr)
        VirtualFreeEx(proc, remote_path, 0, MEM_RELEASE);

    CloseHandle(proc);
    return result;
}
