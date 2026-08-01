#pragma once
//
// Violet - native hashes and the call helper
//
// Every hash below was fetched from the CitizenFX native database during
// development, not recalled from memory. That distinction matters: a single
// wrong hex digit means calling a completely different engine function with
// arguments meant for another, and the result is a crash with no clue as to
// why. If you add one, look it up - do not type it from memory.
//
// Weapon and model hashes are deliberately absent. GET_HASH_KEY computes them
// at runtime from the string, so "WEAPON_CARBINERIFLE" is both self-documenting
// and impossible to get subtly wrong.
//
#include "game/scripthook.hpp"

#include <cstdint>

namespace violet::game::natives
{
    // ---- player / ped ----
    inline constexpr std::uint64_t PLAYER_PED_ID               = 0xD80958FC74E988A6;
    inline constexpr std::uint64_t PLAYER_ID                   = 0x4F8644AF03D0E0D6;
    inline constexpr std::uint64_t SET_ENTITY_INVINCIBLE       = 0x3882114BDE571AD4;
    inline constexpr std::uint64_t SET_ENTITY_HEALTH           = 0x6B76DC1F3AE6E6A3;
    inline constexpr std::uint64_t GET_ENTITY_MAX_HEALTH       = 0x15D757606D170C3C;
    inline constexpr std::uint64_t SET_PED_ARMOUR              = 0xCEA04D83135264CC;
    inline constexpr std::uint64_t GET_VEHICLE_PED_IS_IN       = 0x9A9112A0FE9A4713;

    // ---- wanted level ----
    inline constexpr std::uint64_t SET_PLAYER_WANTED_LEVEL     = 0x39FF19C64EF7DA5B;
    inline constexpr std::uint64_t SET_PLAYER_WANTED_LEVEL_NOW = 0xE0A7D1E497FFCD6F;

    // ---- weapons ----
    inline constexpr std::uint64_t GIVE_WEAPON_TO_PED          = 0xBF0FD6E56C964FCB;
    inline constexpr std::uint64_t SET_PED_INFINITE_AMMO_CLIP  = 0x183DADC6AA953186;

    // ---- position ----
    inline constexpr std::uint64_t SET_ENTITY_COORDS           = 0x06843DA7060A026B;
    inline constexpr std::uint64_t GET_ENTITY_COORDS           = 0x3FEF770D40960D5A;
    inline constexpr std::uint64_t GET_GROUND_Z_FOR_3D_COORD   = 0xC906A7DAB05C8D2B;

    // ---- waypoint ----
    inline constexpr std::uint64_t IS_WAYPOINT_ACTIVE          = 0x1DD1F58F493F1DA5;
    inline constexpr std::uint64_t GET_FIRST_BLIP_INFO_ID      = 0x1BEDE233E6CD2A1F;
    inline constexpr std::uint64_t GET_BLIP_INFO_ID_COORD      = 0xFA7C7F0AADF25D09;

    // ---- world ----
    inline constexpr std::uint64_t SET_CLOCK_TIME              = 0x47C3B5848C3E45D8;
    inline constexpr std::uint64_t SET_WEATHER_TYPE_NOW_PERSIST= 0xED712CA327900C8A;

    // ---- misc ----
    inline constexpr std::uint64_t GET_HASH_KEY                = 0xD24D37CC275948CC;
}

namespace violet::game
{
    // ScriptHookV's Vector3 carries four bytes of padding after each component,
    // because the engine returns them in that shape. Reading it as three packed
    // floats gives you x, garbage, y.
    struct Vector3
    {
        float x = 0.0f; std::uint32_t _pad0 = 0;
        float y = 0.0f; std::uint32_t _pad1 = 0;
        float z = 0.0f; std::uint32_t _pad2 = 0;
    };

    namespace detail
    {
        // Arguments are pushed as raw 64-bit slots. A float must go across as
        // its BIT PATTERN, not converted to an integer - push 1.0f as the
        // number 1 and the engine reads 1.4e-45.
        template <typename T>
        void push_one(T value)
        {
            std::uint64_t slot = 0;
            static_assert(sizeof(T) <= sizeof(std::uint64_t), "argument too large");
            std::memcpy(&slot, &value, sizeof(T));
            native_push(slot);
        }
    }

    // Call a native. Only legal from inside the script thread.
    //
    //   invoke<int>(natives::PLAYER_PED_ID);
    //   invoke<void>(natives::SET_ENTITY_HEALTH, ped, 200);
    template <typename Return = void, typename... Args>
    Return invoke(std::uint64_t hash, Args... args)
    {
        native_init(hash);
        (detail::push_one(args), ...);

        std::uint64_t* result = native_call();

        if constexpr (!std::is_void_v<Return>)
        {
            Return value{};
            if (result != nullptr)
                std::memcpy(&value, result, sizeof(Return));
            return value;
        }
    }
}
