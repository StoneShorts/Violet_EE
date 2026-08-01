#include "game/features.hpp"

#include "core/log.hpp"
#include "game/lobby.hpp"
#include "game/natives.hpp"
#include "game/scripthook.hpp"

#include <cstring>

namespace violet::game
{
namespace
{
    State g_state;

    // Weapon MODEL names rather than hashes, on purpose. GET_HASH_KEY turns
    // these into hashes at runtime, so the table stays readable and there is no
    // opportunity to mistype a 32-bit constant that would silently give you the
    // wrong gun - or nothing at all.
    constexpr WeaponEntry k_weapons[] = {
        { "Pistol",            "WEAPON_PISTOL"          },
        { "Combat Pistol",     "WEAPON_COMBATPISTOL"    },
        { "AP Pistol",         "WEAPON_APPISTOL"        },
        { "Pistol .50",        "WEAPON_PISTOL50"        },
        { "Micro SMG",         "WEAPON_MICROSMG"        },
        { "SMG",               "WEAPON_SMG"             },
        { "Assault Rifle",     "WEAPON_ASSAULTRIFLE"    },
        { "Carbine Rifle",     "WEAPON_CARBINERIFLE"    },
        { "Advanced Rifle",    "WEAPON_ADVANCEDRIFLE"   },
        { "MG",                "WEAPON_MG"              },
        { "Combat MG",         "WEAPON_COMBATMG"        },
        { "Pump Shotgun",      "WEAPON_PUMPSHOTGUN"     },
        { "Sawn-off Shotgun",  "WEAPON_SAWNOFFSHOTGUN"  },
        { "Assault Shotgun",   "WEAPON_ASSAULTSHOTGUN"  },
        { "Sniper Rifle",      "WEAPON_SNIPERRIFLE"     },
        { "Heavy Sniper",      "WEAPON_HEAVYSNIPER"     },
        { "Grenade Launcher",  "WEAPON_GRENADELAUNCHER" },
        { "RPG",               "WEAPON_RPG"             },
        { "Minigun",           "WEAPON_MINIGUN"         },
        { "Grenade",           "WEAPON_GRENADE"         },
        { "Sticky Bomb",       "WEAPON_STICKYBOMB"      },
        { "Molotov",           "WEAPON_MOLOTOV"         },
        { "Knife",             "WEAPON_KNIFE"           },
        { "Baseball Bat",      "WEAPON_BAT"             },
        { "Crowbar",           "WEAPON_CROWBAR"         },
        { "Parachute",         "WEAPON_PARACHUTE"       },
    };

    // Weather names as the engine knows them; index is what the UI picks.
    constexpr const char* k_weather[] = {
        "EXTRASUNNY", "CLEAR", "CLOUDS", "SMOG", "FOGGY", "OVERCAST",
        "RAIN", "THUNDER", "CLEARING", "NEUTRAL", "SNOW", "BLIZZARD",
        "SNOWLIGHT", "XMAS", "HALLOWEEN",
    };

    std::uint32_t hash_of(const char* text)
    {
        return invoke<std::uint32_t>(natives::GET_HASH_KEY, text);
    }

    void give_weapon(int ped, const char* model)
    {
        // GIVE_WEAPON_TO_PED(ped, hash, ammo, isHidden, equipNow)
        invoke<void>(natives::GIVE_WEAPON_TO_PED, ped, hash_of(model), 9999, false, true);
    }

    void teleport_to_waypoint(int ped)
    {
        if (!invoke<bool>(natives::IS_WAYPOINT_ACTIVE))
        {
            g_state.last_result = Result_NoWaypoint;
            return;
        }

        // Blip sprite 4 is the player-placed waypoint.
        const int blip = invoke<int>(natives::GET_FIRST_BLIP_INFO_ID, 4);
        const Vector3 target = invoke<Vector3>(natives::GET_BLIP_INFO_ID_COORD, blip);

        // A waypoint has no height - the map is 2D. So we ask the engine for
        // the ground level, sweeping downward from high altitude.
        //
        // GET_GROUND_Z only answers for terrain that is actually streamed in,
        // and the destination is usually miles away and not loaded yet. Hence
        // the ladder: try a series of heights and take the first that resolves.
        float ground = 0.0f;
        bool  found  = false;

        for (const float probe : { 1000.0f, 800.0f, 600.0f, 400.0f, 200.0f,
                                   100.0f, 50.0f, 20.0f })
        {
            if (invoke<bool>(natives::GET_GROUND_Z_FOR_3D_COORD,
                             target.x, target.y, probe, &ground, false))
            {
                found = true;
                break;
            }
        }

        // If nothing resolved, drop the player in slightly high rather than
        // refusing. Better to fall a short way than to do nothing.
        const float z = found ? ground + 1.0f : 300.0f;

        // Teleport whatever the player is actually controlling. Moving the ped
        // out of a moving car tends to end badly for the car.
        const int vehicle = invoke<int>(natives::GET_VEHICLE_PED_IS_IN, ped, false);
        const int entity  = vehicle != 0 ? vehicle : ped;

        invoke<void>(natives::SET_ENTITY_COORDS, entity,
                     target.x, target.y, z,
                     false, false, false, true);

        g_state.last_result = found ? Result_Ok : Result_NoGround;
    }
}

State& state() { return g_state; }

const WeaponEntry* weapon_list(std::size_t& count)
{
    count = std::size(k_weapons);
    return k_weapons;
}

const char* const* weather_list(std::size_t& count)
{
    count = std::size(k_weather);
    return k_weather;
}

// ---------------------------------------------------------------------------
// features_tick - the script thread
// ---------------------------------------------------------------------------

void features_tick()
{
    const int ped = invoke<int>(natives::PLAYER_PED_ID);
    const int player = invoke<int>(natives::PLAYER_ID);

    g_state.player_ped = ped;

    // Publish position for the UI to display. Cheap, and it is the clearest
    // signal that the whole native pipeline is genuinely working.
    const Vector3 pos = invoke<Vector3>(natives::GET_ENTITY_COORDS, ped, true);
    g_state.pos_x = pos.x;
    g_state.pos_y = pos.y;
    g_state.pos_z = pos.z;

    g_state.in_vehicle = invoke<int>(natives::GET_VEHICLE_PED_IS_IN, ped, false) != 0;

    // ---- continuous toggles ----
    //
    // Re-applied every frame rather than set once. The game clears several of
    // these by itself - on respawn, on mission transitions, on entering a
    // vehicle - so "set it once" silently stops working after a while.
    invoke<void>(natives::SET_ENTITY_INVINCIBLE, ped, g_state.god_mode.load());

    if (g_state.infinite_ammo.load())
        invoke<void>(natives::SET_PED_INFINITE_AMMO_CLIP, ped, true);

    if (g_state.never_wanted.load())
        invoke<void>(natives::SET_PLAYER_WANTED_LEVEL_NOW, player, false);

    // ---- one-shot requests ----
    if (g_state.want_heal.exchange(false))
    {
        const int max_health = invoke<int>(natives::GET_ENTITY_MAX_HEALTH, ped);
        invoke<void>(natives::SET_ENTITY_HEALTH, ped, max_health);
        g_state.last_result = Result_Ok;
    }

    if (g_state.want_armour.exchange(false))
    {
        invoke<void>(natives::SET_PED_ARMOUR, ped, 100);
        g_state.last_result = Result_Ok;
    }

    if (const int index = g_state.want_weapon.exchange(-1); index >= 0)
    {
        if (index < static_cast<int>(std::size(k_weapons)))
        {
            give_weapon(ped, k_weapons[index].model);
            g_state.last_result = Result_Ok;
        }
    }

    if (g_state.want_all_weapons.exchange(false))
    {
        for (const auto& weapon : k_weapons)
            give_weapon(ped, weapon.model);
        g_state.last_result = Result_Ok;
    }

    if (g_state.want_teleport_waypoint.exchange(false))
        teleport_to_waypoint(ped);

    if (const int level = g_state.set_wanted_level.exchange(-1); level >= 0)
    {
        invoke<void>(natives::SET_PLAYER_WANTED_LEVEL, player, level, false);
        invoke<void>(natives::SET_PLAYER_WANTED_LEVEL_NOW, player, false);
        g_state.last_result = Result_Ok;
    }

    if (const int hour = g_state.set_clock_hour.exchange(-1); hour >= 0)
    {
        invoke<void>(natives::SET_CLOCK_TIME, hour, 0, 0);
        g_state.last_result = Result_Ok;
    }

    if (const int weather = g_state.set_weather.exchange(-1); weather >= 0)
    {
        if (weather < static_cast<int>(std::size(k_weather)))
        {
            invoke<void>(natives::SET_WEATHER_TYPE_NOW_PERSIST, k_weather[weather]);
            g_state.last_result = Result_Ok;
        }
    }

    // The offline lobby drives itself from here - same thread, same frame.
    lobby_tick();
}
}
