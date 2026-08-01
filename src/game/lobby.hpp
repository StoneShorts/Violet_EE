#pragma once
//
// Violet - the offline lobby
//
// ---------------------------------------------------------------------------
// What this is
// ---------------------------------------------------------------------------
//
// Story Mode populated with NPCs that behave like other players in a GTA Online
// session: they roam, they carry weapons, they fight each other and you, they
// have gamertags floating over their heads and blips on the minimap, and they
// come back after they die.
//
// It is not networking. There is no server, nothing connects anywhere. It is a
// behaviour state machine driving ordinary spawned peds, which is what makes it
// possible offline at all.
//
// ---------------------------------------------------------------------------
// How it stays out of the way
// ---------------------------------------------------------------------------
//
// Same threading rule as everything else: the UI writes to atomics, and
// lobby_tick() runs on the game's script thread and does the work. The UI reads
// bots back through a snapshot rather than touching the live list, so the
// render thread never walks a vector the script thread might be resizing.
//
// Tasks are issued on STATE CHANGE, not every frame. Re-issuing TASK_COMBAT_PED
// sixty times a second restarts the task sixty times a second, and the ped
// stands there twitching instead of fighting.
//
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace violet::game
{
    struct LobbyConfig
    {
        std::atomic<bool>  enabled{ false };
        std::atomic<int>   desired_bots{ 8 };
        std::atomic<float> spawn_radius{ 60.0f };

        std::atomic<bool>  hostile_to_player{ true };
        std::atomic<bool>  fight_each_other{ true };
        std::atomic<int>   accuracy{ 35 };          // 0-100
        std::atomic<bool>  give_weapons{ true };

        std::atomic<bool>  show_blips{ true };
        std::atomic<bool>  show_nametags{ true };

        std::atomic<bool>  want_clear{ false };
        std::atomic<bool>  want_respawn_all{ false };
    };

    LobbyConfig& lobby_config();

    // Is the lobby usable? False when a required native hash is still unknown,
    // in which case the UI explains rather than offering a dead button.
    bool lobby_available();
    const char* lobby_unavailable_reason();

    enum class BotState : int { Spawning, Wander, Combat, Dead };

    // What the UI is allowed to see. A flat snapshot, copied under a lock once
    // per frame, so the render thread never touches live state.
    struct BotView
    {
        int      ped        = 0;
        BotState state      = BotState::Dead;
        int      health     = 0;
        float    distance   = 0.0f;
        bool     on_screen  = false;
        float    screen_x   = 0.0f;   // 0..1 normalised
        float    screen_y   = 0.0f;
        char     name[24]{};
    };

    // Runs on the script thread, once per game frame.
    void lobby_tick();

    // Remove every bot. Safe to call when the lobby was never started.
    void lobby_shutdown();

    // Copy the current bots out for the UI. Returns how many were written.
    std::size_t lobby_snapshot(BotView* out, std::size_t capacity);

    int lobby_alive_count();
    int lobby_total_count();
}
