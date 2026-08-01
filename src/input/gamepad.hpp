#pragma once
//
// Violet - controller input
//
// ---------------------------------------------------------------------------
// Why we read the pad ourselves when ImGui already supports gamepads
// ---------------------------------------------------------------------------
//
// ImGui's Win32 backend does handle gamepad navigation - but only for input it
// receives while our window is focused and processing messages. When Violet is
// CLOSED, our overlay is click-through and never focused, so ImGui sees nothing
// at all.
//
// The open/close chord therefore has to be read directly from the hardware,
// exactly like the keyboard hotkey is read with GetAsyncKeyState rather than
// WM_KEYDOWN. Once the menu is open, ImGui takes over for navigation.
//
// XInput is loaded dynamically rather than linked. An injected DLL that
// statically imports a missing library fails to load at all, with a useless
// error - and we would rather lose controller support than lose Violet.
//
#include <cstdint>

namespace violet::input
{
    struct PadState
    {
        bool     connected     = false;
        uint16_t buttons       = 0;
        uint8_t  left_trigger  = 0;
        uint8_t  right_trigger = 0;
        int16_t  left_x  = 0, left_y  = 0;
        int16_t  right_x = 0, right_y = 0;
    };

    // Mirrored from <Xinput.h> so callers don't have to include it.
    namespace pad
    {
        constexpr uint16_t dpad_up       = 0x0001;
        constexpr uint16_t dpad_down     = 0x0002;
        constexpr uint16_t dpad_left     = 0x0004;
        constexpr uint16_t dpad_right    = 0x0008;
        constexpr uint16_t start         = 0x0010;
        constexpr uint16_t back          = 0x0020;
        constexpr uint16_t left_thumb    = 0x0040;
        constexpr uint16_t right_thumb   = 0x0080;
        constexpr uint16_t left_shoulder = 0x0100;
        constexpr uint16_t right_shoulder= 0x0200;
        constexpr uint16_t a             = 0x1000;
        constexpr uint16_t b             = 0x2000;
        constexpr uint16_t x             = 0x4000;
        constexpr uint16_t y             = 0x8000;
    }

    void init();
    void shutdown();

    // Reads the first connected pad. Call once per frame.
    const PadState& poll();

    // Violet's open/close chord: D-pad LEFT + right trigger.
    bool menu_chord_held(const PadState& s);

    // Push this pad state into ImGui as navigation input.
    //
    // We do this ourselves rather than letting ImGui's Win32 backend do it
    // (it is compiled out via IMGUI_IMPL_WIN32_DISABLE_GAMEPAD) for three
    // reasons:
    //
    //   1. The backend only ever polls controller slot 0. We scan all four.
    //   2. The backend only re-checks whether a pad exists on WM_DEVICECHANGE,
    //      which our WS_EX_TOOLWINDOW overlay may never receive - so plugging a
    //      controller in after Violet started would go unnoticed forever.
    //   3. D-pad LEFT is both half of the open chord AND a navigation key.
    //      Owning the mapping lets us suppress the chord's buttons, so opening
    //      the menu doesn't also move the cursor on the way in.
    //
    // Call once per frame, before ImGui::NewFrame().
    void feed_imgui(const PadState& s, bool suppress_chord_buttons);
}
