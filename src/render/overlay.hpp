#pragma once
//
// Violet - the overlay
//
// ---------------------------------------------------------------------------
// The approach, and why
// ---------------------------------------------------------------------------
//
// The usual way to draw over a game is to hook its swapchain's Present and
// render inside the game's own frame. We are deliberately NOT doing that.
//
// Three other things have already hooked this swapchain - NVIDIA's overlay,
// NVIDIA Ansel, and Discord - plus Rockstar's own Social Club renderer. Those
// coexist fine with each other; the problem is that if we add a fifth hook and
// something misbehaves, we have four other people's code to rule out before we
// can trust our own. That is a miserable place to debug your first D3D12 code.
//
// So instead: Violet creates its OWN window - transparent, always on top,
// click-through - with its OWN D3D12 device and swapchain, and simply keeps it
// glued on top of the game's window. We never touch the game's rendering. It
// does not know we exist.
//
// The tradeoffs, stated honestly:
//   + Cannot conflict with any other overlay, by construction.
//   + We own every D3D12 object, so nothing is borrowed or reverse-engineered.
//   + Far less to go wrong.
//   - Requires borderless or windowed mode. Exclusive fullscreen puts the game
//     in direct control of the display and nothing composites on top of it.
//   - Will not appear in ShadowPlay clips or in-game screenshots, because those
//     capture the game's swapchain and we are not in it. Desktop capture works.
//
// ---------------------------------------------------------------------------
// How a window can be transparent AND host a D3D12 swapchain
// ---------------------------------------------------------------------------
//
// The old trick - WS_EX_LAYERED with a colour key - gives you no per-pixel
// alpha: one exact colour becomes fully invisible and everything else is fully
// opaque. Anti-aliased text looks awful and any black pixel in your UI becomes
// a hole.
//
// The modern answer is DirectComposition. We create the window with
// WS_EX_NOREDIRECTIONBITMAP (meaning "this window has no normal GDI drawing
// surface, I will supply its contents myself"), create a swapchain with
// CreateSwapChainForComposition and DXGI_ALPHA_MODE_PREMULTIPLIED, and hand
// that swapchain to a DirectComposition visual as its content. The desktop
// compositor then blends our per-pixel alpha over whatever is behind us.
//
#include <cstdint>

namespace violet::render
{
    // Creates the window, the D3D12 device, the swapchain and ImGui, then runs
    // the message + render loop until the user unloads. Returns when done.
    //
    // `self` is our DLL's module handle, needed to register a window class.
    void run_overlay(void* self);

    // Is the menu currently open? Drives click-through and input focus.
    bool menu_visible();
    void set_menu_visible(bool visible);

    // Ask the overlay to shut down and unload Violet from the process.
    //
    // This exits the render loop, which tears down D3D12 and the window, after
    // which main.cpp calls FreeLibraryAndExitThread. The unload is clean enough
    // that you can inject a fresh build immediately without restarting the game
    // - which is the main reason to have it.
    void request_unload();
}
