#pragma once
//
// Violet - the cheats
//
// ---------------------------------------------------------------------------
// The threading rule, which is the whole design
// ---------------------------------------------------------------------------
//
// Natives may only be called from the game's script thread. The menu runs on
// Violet's own render thread. Those are different threads, and calling a native
// from the wrong one reads engine state while the engine is mutating it - which
// crashes, though often not immediately, which is worse.
//
// So nothing in the UI ever calls a native. The UI only writes to the State
// struct below. Once per game frame, features_tick() runs on the script thread,
// reads that state, and does the actual work.
//
// Toggles (god mode, infinite ammo) are re-applied every tick, because the game
// resets a lot of these itself. One-shot actions (heal, teleport, give weapon)
// are requests: the UI raises a flag, the script thread performs it and lowers
// the flag again.
//
#include <atomic>
#include <cstdint>

namespace violet::game
{
    struct State
    {
        // ---- continuous toggles, re-applied every frame ----
        std::atomic<bool> god_mode{ false };
        std::atomic<bool> infinite_ammo{ false };
        std::atomic<bool> never_wanted{ false };

        // ---- one-shot requests, cleared once performed ----
        std::atomic<bool> want_heal{ false };
        std::atomic<bool> want_armour{ false };
        std::atomic<bool> want_teleport_waypoint{ false };
        std::atomic<bool> want_all_weapons{ false };

        // Index into the weapon list, or -1 for none pending.
        std::atomic<int> want_weapon{ -1 };

        // -1 means "leave it alone".
        std::atomic<int> set_wanted_level{ -1 };
        std::atomic<int> set_clock_hour{ -1 };
        std::atomic<int> set_weather{ -1 };

        // ---- read back by the UI, written by the script thread ----
        std::atomic<int>   player_ped{ 0 };
        std::atomic<float> pos_x{ 0.0f };
        std::atomic<float> pos_y{ 0.0f };
        std::atomic<float> pos_z{ 0.0f };
        std::atomic<bool>  in_vehicle{ false };

        // Last thing that happened, for the UI to show.
        std::atomic<int> last_result{ 0 };   // see ResultCode
    };

    enum ResultCode : int
    {
        Result_None = 0,
        Result_Ok,
        Result_NoWaypoint,
        Result_NoGround,
    };

    State& state();

    // Called once per game frame ON THE SCRIPT THREAD. The only place in Violet
    // that may call a native.
    void features_tick();

    // ---- data the UI needs ----
    struct WeaponEntry { const char* label; const char* model; };
    const WeaponEntry* weapon_list(std::size_t& count);

    const char* const* weather_list(std::size_t& count);
}
