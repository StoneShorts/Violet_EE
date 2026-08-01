#include "input/gamepad.hpp"

#include "core/log.hpp"

#include <Windows.h>
#include <Xinput.h>

#include "imgui.h"

#include <cstdlib>

namespace violet::input
{
namespace
{
    using XInputGetStateFn = DWORD (WINAPI*)(DWORD, XINPUT_STATE*);

    HMODULE          g_dll       = nullptr;
    XInputGetStateFn g_get_state = nullptr;
    PadState         g_state;

    // Which controller slot we last found a pad in. Re-scanning all four slots
    // every frame is wasteful when nothing is plugged in, so we remember the
    // good one and only sweep occasionally.
    int g_slot            = -1;
    int g_frames_to_rescan = 0;

    // A deliberate pull, not a brush. Note this does NOT protect against the
    // chord firing while driving, since the trigger is pinned at 255 then -
    // the hold delay below is what handles that case.
    constexpr uint8_t k_trigger_threshold = 160;

    // The chord must be held this long before it counts. Without it, D-pad left
    // during hard acceleration - a completely ordinary thing to do in a car -
    // would pop the menu open.
    constexpr uint64_t k_chord_hold_ms = 250;
}

void init()
{
    // Newest first. 1_4 ships with Windows 8 and later, so on Windows 11 the
    // first one always wins; the others are there so this code stays correct
    // if it is ever run somewhere older.
    for (const wchar_t* name : { L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll" })
    {
        g_dll = LoadLibraryW(name);
        if (g_dll != nullptr)
        {
            g_get_state = reinterpret_cast<XInputGetStateFn>(
                GetProcAddress(g_dll, "XInputGetState"));

            if (g_get_state != nullptr)
            {
                VIOLET_INFO("  xinput: loaded {}",
                            name[6] == L'1' ? "xinput1_4.dll" : "xinput (legacy)");
                return;
            }

            FreeLibrary(g_dll);
            g_dll = nullptr;
        }
    }

    VIOLET_WARN("  xinput: not available - controller support disabled");
}

void shutdown()
{
    if (g_dll != nullptr)
    {
        FreeLibrary(g_dll);
        g_dll = nullptr;
    }
    g_get_state = nullptr;
}

const PadState& poll()
{
    g_state = PadState{};

    if (g_get_state == nullptr)
        return g_state;

    XINPUT_STATE xs{};
    bool have = false;

    // Fast path: the slot that worked last time.
    if (g_slot >= 0 && g_get_state(static_cast<DWORD>(g_slot), &xs) == ERROR_SUCCESS)
    {
        have = true;
    }
    else if (--g_frames_to_rescan <= 0)
    {
        g_frames_to_rescan = 120;   // ~2 seconds at 60 fps
        g_slot = -1;

        for (DWORD i = 0; i < XUSER_MAX_COUNT; ++i)
        {
            if (g_get_state(i, &xs) == ERROR_SUCCESS)
            {
                g_slot = static_cast<int>(i);
                have   = true;

                // Log where the sticks sit the moment we find the pad. If the
                // controller is being left alone, these should be near zero -
                // anything past the deadzone here is physical drift, and it is
                // the first thing to check if the menu starts behaving as
                // though a direction is held down.
                VIOLET_INFO("controller connected in slot {}", i);
                VIOLET_INFO("  resting sticks: L({}, {})  R({}, {})   deadzones L{} R{}",
                            xs.Gamepad.sThumbLX, xs.Gamepad.sThumbLY,
                            xs.Gamepad.sThumbRX, xs.Gamepad.sThumbRY,
                            XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE,
                            XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE);

                const int lx = std::abs(static_cast<int>(xs.Gamepad.sThumbLX));
                const int ly = std::abs(static_cast<int>(xs.Gamepad.sThumbLY));
                const int rx = std::abs(static_cast<int>(xs.Gamepad.sThumbRX));
                const int ry = std::abs(static_cast<int>(xs.Gamepad.sThumbRY));

                if (lx > XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE ||
                    ly > XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE)
                    VIOLET_WARN("  LEFT stick is drifting past its deadzone at rest");

                if (rx > XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE ||
                    ry > XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE)
                    VIOLET_WARN("  RIGHT stick is drifting past its deadzone at rest "
                                "- expect the menu to scroll on its own");

                break;
            }
        }
    }

    if (!have)
        return g_state;

    g_state.connected     = true;
    g_state.buttons       = xs.Gamepad.wButtons;
    g_state.left_trigger  = xs.Gamepad.bLeftTrigger;
    g_state.right_trigger = xs.Gamepad.bRightTrigger;
    g_state.left_x        = xs.Gamepad.sThumbLX;
    g_state.left_y        = xs.Gamepad.sThumbLY;
    g_state.right_x       = xs.Gamepad.sThumbRX;
    g_state.right_y       = xs.Gamepad.sThumbRY;

    return g_state;
}

void feed_imgui(const PadState& s, bool suppress_chord_buttons)
{
    ImGuiIO& io = ImGui::GetIO();

    if (!s.connected)
    {
        io.BackendFlags &= ~ImGuiBackendFlags_HasGamepad;
        return;
    }
    io.BackendFlags |= ImGuiBackendFlags_HasGamepad;

    const auto button = [&](ImGuiKey key, uint16_t mask, bool suppressed = false)
    {
        io.AddKeyEvent(key, !suppressed && (s.buttons & mask) != 0);
    };

    // Maps a raw axis/trigger range onto 0..1. v0 is where the input starts
    // counting (the deadzone edge) and v1 is full deflection - note that for
    // the negative half of a stick, v1 is more negative than v0.
    const auto analog = [&](ImGuiKey key, int value, int v0, int v1, bool suppressed = false)
    {
        float vn = static_cast<float>(value - v0) / static_cast<float>(v1 - v0);
        vn = vn < 0.0f ? 0.0f : (vn > 1.0f ? 1.0f : vn);
        if (suppressed)
            vn = 0.0f;
        io.AddKeyAnalogEvent(key, vn > 0.10f, vn);
    };

    button(ImGuiKey_GamepadStart,     pad::start);
    button(ImGuiKey_GamepadBack,      pad::back);

    button(ImGuiKey_GamepadFaceDown,  pad::a);      // A - activate
    button(ImGuiKey_GamepadFaceRight, pad::b);      // B - cancel / back
    button(ImGuiKey_GamepadFaceLeft,  pad::x);
    button(ImGuiKey_GamepadFaceUp,    pad::y);

    // ---- movement: the D-pad, and ONLY the D-pad --------------------------
    //
    // The left stick deliberately does not move the navigation cursor.
    //
    // It briefly did, and the result was a menu that scrolled through its own
    // items forever without anyone touching it. An analogue stick almost never
    // rests at exactly zero - a little wear, and it sits permanently past the
    // deadzone. That reads as a direction held down, and ImGui quite correctly
    // repeats a held navigation key. The menu walks itself.
    //
    // A D-pad is digital. It cannot drift. So navigation is digital only, and
    // the sticks are used exclusively for analogue jobs (scrolling), where a
    // small resting offset produces a small harmless value instead of an
    // infinitely repeating keypress.
    constexpr int rz = XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE;

    io.AddKeyEvent(ImGuiKey_GamepadDpadUp,    (s.buttons & pad::dpad_up)    != 0);
    io.AddKeyEvent(ImGuiKey_GamepadDpadDown,  (s.buttons & pad::dpad_down)  != 0);
    io.AddKeyEvent(ImGuiKey_GamepadDpadRight, (s.buttons & pad::dpad_right) != 0);
    io.AddKeyEvent(ImGuiKey_GamepadDpadLeft,
                   (s.buttons & pad::dpad_left) != 0 && !suppress_chord_buttons);

    // ---- bumpers ----------------------------------------------------------
    //
    // Deliberately NOT page-jump keys. Moving around is the D-pad and the left
    // stick, four directions, one predictable behaviour - rather than a second
    // way to move that travels a different distance per press.
    //
    // They are still forwarded, which costs nothing and buys one thing: ImGui
    // aliases L1/R1 to NavGamepadTweakSlow and NavGamepadTweakFast, so holding
    // a bumper scales scrolling by 1/10x or 10x. That only has an effect while
    // you are already scrolling with the right stick, so it cannot surprise you
    // in the middle of navigating.
    button(ImGuiKey_GamepadL1, pad::left_shoulder);
    button(ImGuiKey_GamepadR1, pad::right_shoulder);

    button(ImGuiKey_GamepadL3, pad::left_thumb);
    button(ImGuiKey_GamepadR3, pad::right_thumb);

    analog(ImGuiKey_GamepadL2, s.left_trigger,  XINPUT_GAMEPAD_TRIGGER_THRESHOLD, 255);
    analog(ImGuiKey_GamepadR2, s.right_trigger, XINPUT_GAMEPAD_TRIGGER_THRESHOLD, 255,
           suppress_chord_buttons);

    // ---- scrolling: the RIGHT stick ---------------------------------------
    //
    // Deliberately crossed over. ImGui scrolls from its LStick keys and does
    // not consume the RStick keys at all, so feeding the physical right stick
    // into the LStick slots is what actually produces right-stick scrolling.
    // Sign convention: XInput Y is positive up, and ImGui's scroll grows
    // downward, so pushing the stick down maps to LStickDown and scrolls down.
    analog(ImGuiKey_GamepadLStickLeft,  s.right_x, -rz, -32768);
    analog(ImGuiKey_GamepadLStickRight, s.right_x,  rz,  32767);
    analog(ImGuiKey_GamepadLStickUp,    s.right_y,  rz,  32767);
    analog(ImGuiKey_GamepadLStickDown,  s.right_y, -rz, -32768);
}

bool menu_chord_held(const PadState& s)
{
    static uint64_t held_since = 0;

    const bool raw = s.connected &&
                     (s.buttons & pad::dpad_left) != 0 &&
                     s.right_trigger >= k_trigger_threshold;

    if (!raw)
    {
        held_since = 0;
        return false;
    }

    const uint64_t now = GetTickCount64();
    if (held_since == 0)
    {
        held_since = now;
        return false;
    }

    return (now - held_since) >= k_chord_hold_ms;
}
}
