//
// testhost.exe - a stand-in for GTA, for testing Violet without launching it.
//
// This is now a real 1280x720 window rather than a message box, because Violet
// has grown an overlay that tracks its host window's position and size. Testing
// that against a resizable window we control is far faster than relaunching a
// 90 MB game every time, and if something crashes it costs nothing.
//
// The background is painted a flat colour on purpose: it makes it immediately
// obvious whether Violet's transparency is actually working. If DirectComposition
// is set up correctly you will see this colour through the translucent parts of
// the menu. If it is broken you will see black, or nothing at all.
//
#include <Windows.h>
#include <string>

namespace
{
    LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
    {
        switch (msg)
        {
            case WM_PAINT:
            {
                PAINTSTRUCT ps{};
                const HDC dc = BeginPaint(hwnd, &ps);

                RECT rc{};
                GetClientRect(hwnd, &rc);

                const HBRUSH brush = CreateSolidBrush(RGB(28, 104, 76));
                FillRect(dc, &rc, brush);
                DeleteObject(brush);

                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, RGB(230, 240, 235));

                const std::wstring text =
                    L"Violet test host  -  pid " + std::to_wstring(GetCurrentProcessId()) +
                    L"\n\n"
                    L"Inject:   bin\\inject.exe testhost.exe bin\\Violet.dll\n\n"
                    L"PAGE UP (or D-pad LEFT + right trigger) toggles the menu.\n"
                    L"END unloads Violet.\n\n"
                    L"If transparency works you will see this green through the menu.";

                RECT text_rc = rc;
                text_rc.left   += 40;
                text_rc.top    += 40;
                DrawTextW(dc, text.c_str(), -1, &text_rc, DT_LEFT | DT_TOP | DT_WORDBREAK);

                EndPaint(hwnd, &ps);
                return 0;
            }

            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;

            default:
                break;
        }

        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance     = instance;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"VioletTestHost";
    RegisterClassExW(&wc);

    const HWND hwnd = CreateWindowExW(
        0, wc.lpszClassName, L"Violet test host",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1280, 720,
        nullptr, nullptr, instance, nullptr);

    if (hwnd == nullptr)
        return 1;

    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}
