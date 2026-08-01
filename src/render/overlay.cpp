#include "render/overlay.hpp"

#include "core/log.hpp"
#include "input/gamepad.hpp"
#include "render/srv_heap.hpp"
#include "ui/menu.hpp"

#include <Windows.h>
#include <d3d12.h>
#include <dxgi1_4.h>
#include <dcomp.h>
#include <wrl/client.h>

#include <algorithm>
#include <string>

#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx12.h"

// The Win32 backend deliberately does not include <windows.h> in its header, so
// it asks you to forward-declare this yourself and call it from your WndProc.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

using Microsoft::WRL::ComPtr;

namespace violet::render
{
namespace
{
    // Two back buffers is the right default for a composition swapchain: enough
    // to keep the GPU fed without adding a third frame of input latency.
    constexpr int  k_frame_count   = 2;
    constexpr int  k_srv_capacity  = 64;
    constexpr auto k_back_buffer_format = DXGI_FORMAT_B8G8R8A8_UNORM;

    // Each frame in flight needs its own command allocator. You cannot reset an
    // allocator while the GPU is still executing commands recorded from it, so
    // with two frames in flight you need two allocators and a fence to know
    // when each is safe to reuse.
    struct FrameContext
    {
        ComPtr<ID3D12CommandAllocator> allocator;
        UINT64                         fence_value = 0;
    };

    // ---- window ----
    HWND      g_hwnd       = nullptr;
    HWND      g_game_hwnd  = nullptr;
    ATOM      g_wnd_class  = 0;
    HINSTANCE g_instance   = nullptr;
    RECT      g_tracked{};
    bool      g_menu_open  = false;
    bool      g_running    = true;
    bool      g_log_candidates    = true;   // narrate the window search only once
    int       g_game_missing_ticks = 0;

    violet::input::PadState g_pad;
    bool                    g_chord_active = false;

    // ---- d3d12 ----
    ComPtr<ID3D12Device>              g_device;
    ComPtr<ID3D12CommandQueue>        g_queue;
    ComPtr<ID3D12GraphicsCommandList> g_cmd_list;
    ComPtr<ID3D12DescriptorHeap>      g_rtv_heap;
    ComPtr<ID3D12DescriptorHeap>      g_srv_heap;
    ComPtr<ID3D12Fence>               g_fence;
    ComPtr<IDXGISwapChain3>           g_swapchain;
    ComPtr<ID3D12Resource>            g_back_buffers[k_frame_count];
    D3D12_CPU_DESCRIPTOR_HANDLE       g_rtv_handles[k_frame_count]{};
    FrameContext                      g_frames[k_frame_count];
    SrvHeapAllocator                  g_srv_alloc;
    HANDLE                            g_fence_event         = nullptr;
    UINT64                            g_fence_last_signaled = 0;
    UINT                              g_frame_index         = 0;

    // ---- directcomposition ----
    ComPtr<IDCompositionDevice> g_dcomp_device;
    ComPtr<IDCompositionTarget> g_dcomp_target;
    ComPtr<IDCompositionVisual> g_dcomp_visual;

    // -----------------------------------------------------------------------
    // finding the game's window
    // -----------------------------------------------------------------------

    // Win32 hands us UTF-16; std::format and our log want UTF-8.
    std::string narrow(const wchar_t* s)
    {
        if (s == nullptr || *s == L'\0')
            return {};

        const int needed = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
        if (needed <= 1)
            return {};

        std::string out(static_cast<std::size_t>(needed - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), needed, nullptr, nullptr);
        return out;
    }

    struct WindowSearch
    {
        DWORD pid       = 0;
        HWND  best      = nullptr;
        LONG  best_area = 0;
    };

    BOOL CALLBACK enum_window_proc(HWND hwnd, LPARAM param)
    {
        auto* search = reinterpret_cast<WindowSearch*>(param);

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);

        if (pid != search->pid)          return TRUE;   // someone else's window
        if (hwnd == g_hwnd)              return TRUE;   // our own overlay
        if (!IsWindowVisible(hwnd))      return TRUE;
        if (GetWindow(hwnd, GW_OWNER))   return TRUE;   // owned popup, not the main window

        RECT r{};
        if (!GetWindowRect(hwnd, &r))    return TRUE;

        const LONG area = (r.right - r.left) * (r.bottom - r.top);
        if (area <= 0)                   return TRUE;

        wchar_t cls[128]{};
        GetClassNameW(hwnd, cls, 128);

        wchar_t title[128]{};
        GetWindowTextW(hwnd, title, 128);

        // Our own AllocConsole window belongs to this process too, so it turns
        // up here. Harmless while the game window is bigger - but if the game
        // were ever windowed small, the console would win the size contest and
        // we would glue the overlay to our own log. Exclude it explicitly.
        if (wcscmp(cls, L"ConsoleWindowClass") == 0)
            return TRUE;

        // Logged rather than hardcoded: we do not want to bake in a window class
        // name that a game update could change. The heuristic below just picks
        // the biggest visible unowned window, which is reliably the game - but
        // now we get to SEE what GTA's window is actually called.
        if (g_log_candidates)
            VIOLET_INFO("  candidate: class='{}' title='{}' {}x{}",
                        narrow(cls), narrow(title), r.right - r.left, r.bottom - r.top);

        if (area > search->best_area)
        {
            search->best_area = area;
            search->best      = hwnd;
        }

        return TRUE;
    }

    HWND find_game_window()
    {
        WindowSearch search;
        search.pid = GetCurrentProcessId();
        EnumWindows(enum_window_proc, reinterpret_cast<LPARAM>(&search));
        g_log_candidates = false;   // this runs repeatedly; don't flood the log
        return search.best;
    }

    // Everything we can learn about the game's window from outside it. If the
    // overlay is ever invisible, this block is the first thing to read - it
    // tells you whether the game is windowed, borderless, or has gone exclusive
    // fullscreen (in which case nothing can composite on top of it at all).
    void log_game_window_info()
    {
        RECT window_rect{}, client_rect{};
        GetWindowRect(g_game_hwnd, &window_rect);
        GetClientRect(g_game_hwnd, &client_rect);

        const LONG style    = GetWindowLongW(g_game_hwnd, GWL_STYLE);
        const LONG ex_style = GetWindowLongW(g_game_hwnd, GWL_EXSTYLE);

        MONITORINFO mi{};
        mi.cbSize = sizeof(mi);
        GetMonitorInfoW(MonitorFromWindow(g_game_hwnd, MONITOR_DEFAULTTONEAREST), &mi);

        const bool covers_monitor =
            window_rect.left   <= mi.rcMonitor.left  && window_rect.top    <= mi.rcMonitor.top &&
            window_rect.right  >= mi.rcMonitor.right && window_rect.bottom >= mi.rcMonitor.bottom;

        VIOLET_INFO("  game window   : ({},{}) {}x{}",
                    window_rect.left, window_rect.top,
                    window_rect.right - window_rect.left,
                    window_rect.bottom - window_rect.top);
        VIOLET_INFO("  game client   : {}x{}", client_rect.right, client_rect.bottom);
        VIOLET_INFO("  monitor       : ({},{}) {}x{}",
                    mi.rcMonitor.left, mi.rcMonitor.top,
                    mi.rcMonitor.right - mi.rcMonitor.left,
                    mi.rcMonitor.bottom - mi.rcMonitor.top);
        VIOLET_INFO("  style         : 0x{:08X}   exstyle 0x{:08X}",
                    static_cast<unsigned>(style), static_cast<unsigned>(ex_style));
        VIOLET_INFO("  game topmost  : {}", (ex_style & WS_EX_TOPMOST) ? "yes" : "no");
        VIOLET_INFO("  covers monitor: {}", covers_monitor ? "yes" : "no (windowed)");

        if (covers_monitor)
        {
            VIOLET_INFO("  -> borderless OR exclusive fullscreen (they look identical");
            VIOLET_INFO("     from out here). If Violet is invisible, set Screen Type to");
            VIOLET_INFO("     BORDERLESS: exclusive fullscreen hands the display straight");
            VIOLET_INFO("     to the game and bypasses the desktop compositor entirely,");
            VIOLET_INFO("     so nothing can be drawn on top of it.");
        }
    }

    // Re-assert our place in the always-on-top band.
    //
    // This is the fix for "the overlay works over a test window but vanishes
    // over the game". WS_EX_TOPMOST puts a window in a special z-order band -
    // but within that band, ordering still follows activation. A game that is
    // also topmost and currently focused sits above us, and since we only
    // called SetWindowPos when our tracked rectangle changed, we never climbed
    // back. Periodically re-inserting at the top of the band fixes it, and at
    // twice a second it costs nothing.
    void keep_on_top()
    {
        static ULONGLONG last = 0;

        const ULONGLONG now = GetTickCount64();
        if (now - last < 500)
            return;
        last = now;

        SetWindowPos(g_hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    // -----------------------------------------------------------------------
    // window
    // -----------------------------------------------------------------------

    void apply_click_through(bool click_through)
    {
        LONG_PTR ex = GetWindowLongPtrW(g_hwnd, GWL_EXSTYLE);

        // WS_EX_TRANSPARENT makes hit-testing fall straight through to whatever
        // is underneath, so clicks reach the game. WS_EX_NOACTIVATE stops the
        // window ever stealing focus. When the menu opens we drop both so that
        // keyboard and mouse come to us instead.
        if (click_through)
            ex |= (WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
        else
            ex &= ~(WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);

        SetWindowLongPtrW(g_hwnd, GWL_EXSTYLE, ex);
    }

    LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
    {
        if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp))
            return 1;

        if (msg == WM_DESTROY)
            return 0;

        return DefWindowProcW(hwnd, msg, wp, lp);
    }

    bool create_overlay_window(HINSTANCE instance)
    {
        WNDCLASSEXW wc{};
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = wnd_proc;
        wc.hInstance     = instance;
        wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = L"VioletOverlayWindow";

        g_wnd_class = RegisterClassExW(&wc);
        if (g_wnd_class == 0)
        {
            VIOLET_ERROR("RegisterClassExW failed: {}", GetLastError());
            return false;
        }

        // WS_EX_NOREDIRECTIONBITMAP is the key flag: it tells Windows this
        // window has no ordinary GDI drawing surface, because we are going to
        // supply its contents through DirectComposition instead. Without it the
        // compositor allocates a redirection surface and our alpha is lost.
        //
        // WS_EX_TOOLWINDOW keeps us out of the taskbar and out of alt-tab.
        const DWORD ex_style = WS_EX_NOREDIRECTIONBITMAP | WS_EX_TOPMOST |
                               WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE;

        g_hwnd = CreateWindowExW(ex_style, wc.lpszClassName, L"Violet",
                                 WS_POPUP, 0, 0, 100, 100,
                                 nullptr, nullptr, instance, nullptr);

        if (g_hwnd == nullptr)
        {
            VIOLET_ERROR("CreateWindowExW failed: {}", GetLastError());
            return false;
        }

        ShowWindow(g_hwnd, SW_SHOWNOACTIVATE);
        return true;
    }

    // -----------------------------------------------------------------------
    // d3d12
    // -----------------------------------------------------------------------

    void create_render_targets()
    {
        for (int i = 0; i < k_frame_count; ++i)
        {
            ComPtr<ID3D12Resource> buffer;
            g_swapchain->GetBuffer(static_cast<UINT>(i), IID_PPV_ARGS(&buffer));

            // A render target view is just a descriptor saying "treat this
            // resource as something we can draw into, in this format".
            g_device->CreateRenderTargetView(buffer.Get(), nullptr, g_rtv_handles[i]);
            g_back_buffers[i] = buffer;
        }
    }

    void release_render_targets()
    {
        for (auto& b : g_back_buffers)
            b.Reset();
    }

    bool create_device(UINT width, UINT height)
    {
        if (FAILED(D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&g_device))))
        {
            VIOLET_ERROR("D3D12CreateDevice failed");
            return false;
        }

        D3D12_COMMAND_QUEUE_DESC qd{};
        qd.Type  = D3D12_COMMAND_LIST_TYPE_DIRECT;
        qd.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
        if (FAILED(g_device->CreateCommandQueue(&qd, IID_PPV_ARGS(&g_queue))))
        {
            VIOLET_ERROR("CreateCommandQueue failed");
            return false;
        }

        // RTV heap: one descriptor per back buffer. Not shader-visible - the
        // GPU never reads these through a shader, the command list references
        // them directly.
        D3D12_DESCRIPTOR_HEAP_DESC rtv{};
        rtv.Type           = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
        rtv.NumDescriptors = k_frame_count;
        rtv.Flags          = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
        if (FAILED(g_device->CreateDescriptorHeap(&rtv, IID_PPV_ARGS(&g_rtv_heap))))
        {
            VIOLET_ERROR("CreateDescriptorHeap(RTV) failed");
            return false;
        }

        const UINT rtv_size = g_device->GetDescriptorHandleIncrementSize(
            D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
        auto handle = g_rtv_heap->GetCPUDescriptorHandleForHeapStart();
        for (int i = 0; i < k_frame_count; ++i)
        {
            g_rtv_handles[i] = handle;
            handle.ptr += rtv_size;
        }

        // SRV heap: this one IS shader-visible, because ImGui's pixel shader
        // samples the font atlas out of it.
        D3D12_DESCRIPTOR_HEAP_DESC srv{};
        srv.Type           = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
        srv.NumDescriptors = k_srv_capacity;
        srv.Flags          = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
        if (FAILED(g_device->CreateDescriptorHeap(&srv, IID_PPV_ARGS(&g_srv_heap))))
        {
            VIOLET_ERROR("CreateDescriptorHeap(SRV) failed");
            return false;
        }
        g_srv_alloc.create(g_device.Get(), g_srv_heap.Get(), k_srv_capacity);

        for (auto& f : g_frames)
        {
            if (FAILED(g_device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT,
                                                       IID_PPV_ARGS(&f.allocator))))
            {
                VIOLET_ERROR("CreateCommandAllocator failed");
                return false;
            }
        }

        if (FAILED(g_device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT,
                                               g_frames[0].allocator.Get(), nullptr,
                                               IID_PPV_ARGS(&g_cmd_list))))
        {
            VIOLET_ERROR("CreateCommandList failed");
            return false;
        }
        g_cmd_list->Close();   // command lists are created in the recording state

        if (FAILED(g_device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&g_fence))))
        {
            VIOLET_ERROR("CreateFence failed");
            return false;
        }
        g_fence_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);

        // ---- swapchain ----
        ComPtr<IDXGIFactory4> factory;
        if (FAILED(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory))))
        {
            VIOLET_ERROR("CreateDXGIFactory2 failed");
            return false;
        }

        DXGI_SWAP_CHAIN_DESC1 sd{};
        sd.Width       = std::max(width,  1u);
        sd.Height      = std::max(height, 1u);
        sd.Format      = k_back_buffer_format;
        sd.BufferCount = k_frame_count;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.SwapEffect  = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
        sd.SampleDesc.Count = 1;
        sd.Scaling     = DXGI_SCALING_STRETCH;

        // The single most important line for transparency. PREMULTIPLIED means
        // the compositor expects colour channels already scaled by alpha - and
        // that is exactly what ImGui's blend state produces when you clear the
        // target to transparent black, so the two line up for free.
        sd.AlphaMode   = DXGI_ALPHA_MODE_PREMULTIPLIED;

        ComPtr<IDXGISwapChain1> sc1;
        // Note the first argument: for D3D12 the swapchain is created against
        // the command QUEUE, not the device. DXGI needs the queue so it knows
        // where to insert the present.
        if (FAILED(factory->CreateSwapChainForComposition(g_queue.Get(), &sd, nullptr, &sc1)))
        {
            VIOLET_ERROR("CreateSwapChainForComposition failed");
            return false;
        }
        if (FAILED(sc1.As(&g_swapchain)))
        {
            VIOLET_ERROR("swapchain QueryInterface to IDXGISwapChain3 failed");
            return false;
        }

        create_render_targets();

        // ---- directcomposition: bind the swapchain to the window ----
        if (FAILED(DCompositionCreateDevice(nullptr, IID_PPV_ARGS(&g_dcomp_device))))
        {
            VIOLET_ERROR("DCompositionCreateDevice failed");
            return false;
        }
        if (FAILED(g_dcomp_device->CreateTargetForHwnd(g_hwnd, TRUE, &g_dcomp_target)) ||
            FAILED(g_dcomp_device->CreateVisual(&g_dcomp_visual)) ||
            FAILED(g_dcomp_visual->SetContent(g_swapchain.Get())) ||
            FAILED(g_dcomp_target->SetRoot(g_dcomp_visual.Get())) ||
            FAILED(g_dcomp_device->Commit()))
        {
            VIOLET_ERROR("DirectComposition setup failed");
            return false;
        }

        return true;
    }

    FrameContext* wait_for_next_frame()
    {
        FrameContext* frame = &g_frames[g_frame_index % k_frame_count];
        ++g_frame_index;

        // If this slot still has work outstanding on the GPU, block until the
        // fence says it finished. Only then is its allocator safe to reset.
        if (const UINT64 target = frame->fence_value; target != 0)
        {
            frame->fence_value = 0;
            if (g_fence->GetCompletedValue() < target)
            {
                g_fence->SetEventOnCompletion(target, g_fence_event);
                WaitForSingleObject(g_fence_event, INFINITE);
            }
        }

        return frame;
    }

    void wait_for_gpu_idle()
    {
        if (!g_queue || !g_fence)
            return;

        const UINT64 target = ++g_fence_last_signaled;
        g_queue->Signal(g_fence.Get(), target);

        if (g_fence->GetCompletedValue() < target)
        {
            g_fence->SetEventOnCompletion(target, g_fence_event);
            WaitForSingleObject(g_fence_event, INFINITE);
        }
    }

    void resize(UINT width, UINT height)
    {
        if (width == 0 || height == 0)
            return;

        // Buffers cannot be resized while the GPU might still be reading them.
        wait_for_gpu_idle();
        release_render_targets();

        g_swapchain->ResizeBuffers(k_frame_count, width, height,
                                   k_back_buffer_format, 0);
        create_render_targets();
    }

    void render_frame()
    {
        ImGui_ImplDX12_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        violet::ui::draw();

        ImGui::Render();

        FrameContext* frame = wait_for_next_frame();
        const UINT back_index = g_swapchain->GetCurrentBackBufferIndex();

        frame->allocator->Reset();
        g_cmd_list->Reset(frame->allocator.Get(), nullptr);

        // Resources must be explicitly transitioned between uses in D3D12 -
        // the driver will not infer it for you, and getting it wrong is one of
        // the most common sources of corruption.
        D3D12_RESOURCE_BARRIER barrier{};
        barrier.Type                   = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Transition.pResource   = g_back_buffers[back_index].Get();
        barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
        barrier.Transition.StateAfter  = D3D12_RESOURCE_STATE_RENDER_TARGET;
        g_cmd_list->ResourceBarrier(1, &barrier);

        // Clear to fully transparent black. Every pixel Violet does not draw
        // stays invisible, and the compositor shows the game through it.
        constexpr float clear[4] = { 0.0f, 0.0f, 0.0f, 0.0f };
        g_cmd_list->ClearRenderTargetView(g_rtv_handles[back_index], clear, 0, nullptr);
        g_cmd_list->OMSetRenderTargets(1, &g_rtv_handles[back_index], FALSE, nullptr);

        ID3D12DescriptorHeap* heaps[] = { g_srv_heap.Get() };
        g_cmd_list->SetDescriptorHeaps(1, heaps);

        ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), g_cmd_list.Get());

        std::swap(barrier.Transition.StateBefore, barrier.Transition.StateAfter);
        g_cmd_list->ResourceBarrier(1, &barrier);

        g_cmd_list->Close();

        ID3D12CommandList* lists[] = { g_cmd_list.Get() };
        g_queue->ExecuteCommandLists(1, lists);

        // Present(1, ...) waits for vsync, which conveniently paces this whole
        // loop for us without a sleep or a spin.
        g_swapchain->Present(1, 0);

        const UINT64 signal = ++g_fence_last_signaled;
        g_queue->Signal(g_fence.Get(), signal);
        frame->fence_value = signal;
    }

    // -----------------------------------------------------------------------
    // tracking the game window
    // -----------------------------------------------------------------------

    void update_tracking()
    {
        if (!IsWindow(g_game_hwnd))
        {
            g_game_hwnd = find_game_window();

            if (!g_game_hwnd)
            {
                // The game's window is gone. Allow a few seconds in case this is
                // a transient recreation, then shut down. Now that there is no
                // unload hotkey, this IS how Violet exits: it lives as long as
                // the game does.
                if (++g_game_missing_ticks > 180)   // ~3 s at 60 fps
                {
                    VIOLET_INFO("game window gone - Violet shutting down");
                    g_running = false;
                }
                return;
            }

            g_game_missing_ticks = 0;
            log_game_window_info();
        }

        // Hide ourselves whenever the game is not the active window, so Violet
        // does not float on top of the user's browser after an alt-tab.
        const HWND fg = GetForegroundWindow();
        const bool game_active = (fg == g_game_hwnd || fg == g_hwnd);

        if (!game_active || IsIconic(g_game_hwnd))
        {
            if (IsWindowVisible(g_hwnd))
                ShowWindow(g_hwnd, SW_HIDE);
            return;
        }

        if (!IsWindowVisible(g_hwnd))
            ShowWindow(g_hwnd, SW_SHOWNOACTIVATE);

        keep_on_top();

        RECT r{};
        if (!GetClientRect(g_game_hwnd, &r))
            return;

        // GetClientRect is in client coordinates (always 0,0 based), so convert
        // the top-left corner to screen space to find where to put ourselves.
        POINT top_left{ r.left, r.top };
        ClientToScreen(g_game_hwnd, &top_left);

        const LONG w = r.right - r.left;
        const LONG h = r.bottom - r.top;

        if (top_left.x != g_tracked.left || top_left.y != g_tracked.top ||
            w != g_tracked.right || h != g_tracked.bottom)
        {
            g_tracked = { top_left.x, top_left.y, w, h };

            SetWindowPos(g_hwnd, HWND_TOPMOST, top_left.x, top_left.y, w, h,
                         SWP_NOACTIVATE);

            resize(static_cast<UINT>(w), static_cast<UINT>(h));
            VIOLET_INFO("overlay tracked to {}x{} at ({},{})", w, h, top_left.x, top_left.y);
        }
    }

    void poll_hotkeys()
    {
        // Polled rather than handled via WM_KEYDOWN, deliberately: when the
        // menu is closed our window is click-through and never focused, so it
        // receives no key messages at all. GetAsyncKeyState reads global state
        // and works regardless of who has focus - and the same reasoning is why
        // the controller is read straight from XInput.
        static bool toggle_was_down = false;

        g_pad          = violet::input::poll();
        g_chord_active = violet::input::menu_chord_held(g_pad);

        // END or PAGE UP on the keyboard, D-pad LEFT + right trigger on a pad.
        // There is no unload key any more - Violet lives until the game closes.
        const bool toggle_down = (GetAsyncKeyState(VK_END)   & 0x8000) != 0 ||
                                 (GetAsyncKeyState(VK_PRIOR) & 0x8000) != 0 ||
                                 g_chord_active;

        if (toggle_down && !toggle_was_down)
            set_menu_visible(!g_menu_open);
        toggle_was_down = toggle_down;
    }
}

// ---------------------------------------------------------------------------
// public
// ---------------------------------------------------------------------------

bool menu_visible() { return g_menu_open; }

void request_unload()
{
    VIOLET_INFO("unload requested from the menu");
    g_running = false;
}

void set_menu_visible(bool visible)
{
    if (g_menu_open == visible)
        return;

    g_menu_open = visible;
    apply_click_through(!visible);

    if (visible)
    {
        SetForegroundWindow(g_hwnd);
        VIOLET_INFO("menu opened");
    }
    else
    {
        if (IsWindow(g_game_hwnd))
            SetForegroundWindow(g_game_hwnd);
        VIOLET_INFO("menu closed");
    }
}

void run_overlay(void* self)
{
    g_instance = static_cast<HINSTANCE>(self);

    VIOLET_INFO("--- overlay startup ---------------------------------");

    g_game_hwnd = find_game_window();
    if (!g_game_hwnd)
    {
        VIOLET_ERROR("could not find the game's window - aborting overlay");
        return;
    }

    log_game_window_info();

    RECT client{};
    GetClientRect(g_game_hwnd, &client);

    if (!create_overlay_window(g_instance))
        return;

    // Position over the game immediately, before the swapchain exists.
    //
    // update_tracking() would eventually do this, but it deliberately refuses
    // to while the game is not the foreground window - and during startup it
    // very often isn't. Doing it once here means the swapchain gets created at
    // the right size the first time instead of being resized on frame two.
    {
        POINT top_left{ 0, 0 };
        ClientToScreen(g_game_hwnd, &top_left);
        SetWindowPos(g_hwnd, HWND_TOPMOST, top_left.x, top_left.y,
                     client.right, client.bottom, SWP_NOACTIVATE);
        g_tracked = { top_left.x, top_left.y, client.right, client.bottom };
    }

    if (!create_device(static_cast<UINT>(client.right), static_cast<UINT>(client.bottom)))
    {
        VIOLET_ERROR("D3D12 setup failed - aborting overlay");
        return;
    }
    VIOLET_INFO("  D3D12 device + composition swapchain ready");

    // ---- ImGui ----
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;

    // Without this, ImGui writes an imgui.ini into whatever directory the game
    // happens to be running from. We are a guest in this process; do not leave
    // files lying around in Rockstar's install folder.
    io.IniFilename = nullptr;

    // NOTE: deliberately NOT calling ImGui_ImplWin32_EnableDpiAwareness().
    // That changes DPI awareness for the ENTIRE process - which is GTA, not us.
    // Changing a host process's global state from inside an injected DLL is how
    // you break the thing you are trying to enhance.

    violet::ui::apply_theme();

    ImGui_ImplWin32_Init(g_hwnd);

    ImGui_ImplDX12_InitInfo init{};
    init.Device            = g_device.Get();
    init.CommandQueue      = g_queue.Get();
    init.NumFramesInFlight = k_frame_count;
    init.RTVFormat         = k_back_buffer_format;
    init.DSVFormat         = DXGI_FORMAT_UNKNOWN;   // no depth buffer; it's a 2D overlay
    init.SrvDescriptorHeap = g_srv_heap.Get();
    init.SrvDescriptorAllocFn = [](ImGui_ImplDX12_InitInfo*,
                                   D3D12_CPU_DESCRIPTOR_HANDLE* cpu,
                                   D3D12_GPU_DESCRIPTOR_HANDLE* gpu)
    {
        g_srv_alloc.alloc(cpu, gpu);
    };
    init.SrvDescriptorFreeFn = [](ImGui_ImplDX12_InitInfo*,
                                  D3D12_CPU_DESCRIPTOR_HANDLE cpu,
                                  D3D12_GPU_DESCRIPTOR_HANDLE gpu)
    {
        g_srv_alloc.free(cpu, gpu);
    };

    if (!ImGui_ImplDX12_Init(&init))
    {
        VIOLET_ERROR("ImGui_ImplDX12_Init failed");
        return;
    }

    VIOLET_INFO("  ImGui {} initialised", IMGUI_VERSION);

    violet::input::init();

    VIOLET_INFO("");
    VIOLET_INFO("  END or PAGE UP        toggle the menu");
    VIOLET_INFO("  D-pad LEFT + RT       toggle the menu (hold briefly)");
    VIOLET_INFO("  Violet unloads by itself when the game closes.");

    // ---- main loop ----
    while (g_running)
    {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT)
                g_running = false;
        }

        poll_hotkeys();
        update_tracking();

        // update_tracking() hides us whenever the game is not in front. No
        // sense burning a GPU frame on an invisible window - but we must still
        // sleep, or this becomes a spin loop eating a whole core while the user
        // is alt-tabbed.
        if (IsWindowVisible(g_hwnd))
        {
            // Queued before NewFrame, which is where ImGui consumes input
            // events. Only fed when we are actually going to render - otherwise
            // events would pile up unconsumed while the game is alt-tabbed.
            violet::input::feed_imgui(g_pad, g_chord_active);
            render_frame();
        }
        else
        {
            Sleep(16);
        }
    }

    // ---- teardown ----
    VIOLET_INFO("overlay shutting down");

    wait_for_gpu_idle();

    violet::input::shutdown();

    ImGui_ImplDX12_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    release_render_targets();
    g_srv_alloc.destroy();

    g_dcomp_visual.Reset();
    g_dcomp_target.Reset();
    g_dcomp_device.Reset();
    g_swapchain.Reset();
    g_fence.Reset();
    g_rtv_heap.Reset();
    g_srv_heap.Reset();
    g_cmd_list.Reset();
    for (auto& f : g_frames)
        f.allocator.Reset();
    g_queue.Reset();
    g_device.Reset();

    if (g_fence_event)
    {
        CloseHandle(g_fence_event);
        g_fence_event = nullptr;
    }

    if (g_hwnd)
    {
        DestroyWindow(g_hwnd);
        g_hwnd = nullptr;
    }
    if (g_wnd_class)
    {
        UnregisterClassW(L"VioletOverlayWindow", g_instance);
        g_wnd_class = 0;
    }
}
}
