#include "game/lobby.hpp"

#include "core/log.hpp"
#include "game/natives.hpp"
#include "game/scripthook.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace violet::game
{
namespace
{
    LobbyConfig g_config;

    struct Bot
    {
        int           ped         = 0;
        int           blip        = 0;
        BotState      state       = BotState::Spawning;
        std::uint64_t state_since = 0;
        std::uint64_t respawn_at  = 0;
        int           combat_target = 0;
        std::string   name;
    };

    std::vector<Bot> g_bots;

    // The UI reads through this copy, never the live vector.
    std::mutex           g_snapshot_lock;
    std::vector<BotView> g_snapshot;

    std::uint64_t g_frame = 0;
    bool          g_groups_ready = false;
    std::uint32_t g_group_bots   = 0;
    std::uint32_t g_group_player = 0;

    // ---- randomness --------------------------------------------------------
    //
    // A tiny xorshift rather than std::rand, purely so bot placement and names
    // do not depend on whatever else in the game happens to have called rand().
    std::uint64_t g_rng = 0x9E3779B97F4A7C15ull;

    std::uint32_t next_random()
    {
        g_rng ^= g_rng << 13;
        g_rng ^= g_rng >> 7;
        g_rng ^= g_rng << 17;
        return static_cast<std::uint32_t>(g_rng >> 32);
    }

    float random_range(float lo, float hi)
    {
        return lo + (hi - lo) * (static_cast<float>(next_random() % 10000u) / 10000.0f);
    }

    // ---- flavour -----------------------------------------------------------

    constexpr const char* k_name_prefix[] = {
        "xX", "Lil", "Big", "Mr", "Yung", "Dr", "Its", "Real", "OG", "Sir", "TTV",
    };
    constexpr const char* k_name_core[] = {
        "Sniper", "Griefer", "Trevor", "Money", "Shark", "Ghost", "Reaper",
        "Chaos", "Bandit", "Vortex", "Karma", "Blaze", "Toxic", "Nitro",
        "Havoc", "Phantom", "Killa", "Legend",
    };
    constexpr const char* k_name_suffix[] = {
        "Xx", "420", "69", "_YT", "TV", "99", "007", "", "_HD", "2K",
    };

    std::string make_gamertag()
    {
        const bool use_prefix = (next_random() % 3) == 0;

        std::string name;
        if (use_prefix)
            name += k_name_prefix[next_random() % std::size(k_name_prefix)];

        name += k_name_core[next_random() % std::size(k_name_core)];
        name += k_name_suffix[next_random() % std::size(k_name_suffix)];

        if (name.size() > 20)
            name.resize(20);
        return name;
    }

    // The online player models, so they read as players rather than as
    // pedestrians. Mixed with a few street peds for variety.
    constexpr const char* k_models[] = {
        "mp_m_freemode_01", "mp_f_freemode_01",
        "mp_m_freemode_01", "mp_f_freemode_01",
        "a_m_y_hipster_01", "a_m_y_business_01", "a_f_y_hipster_02",
        "g_m_y_ballasout_01", "g_m_y_lost_01", "s_m_y_dealer_01",
    };

    constexpr const char* k_bot_weapons[] = {
        "WEAPON_PISTOL", "WEAPON_COMBATPISTOL", "WEAPON_MICROSMG", "WEAPON_SMG",
        "WEAPON_ASSAULTRIFLE", "WEAPON_CARBINERIFLE", "WEAPON_PUMPSHOTGUN",
    };

    std::uint32_t hash_of(const char* text)
    {
        return invoke<std::uint32_t>(natives::GET_HASH_KEY, text);
    }

    // ---- relationships -----------------------------------------------------
    //
    // Rather than making every ped hate everything (which turns the whole city
    // hostile), the bots get their own relationship group. Then we only have to
    // set the handful of relationships we actually want.
    void ensure_relationship_groups()
    {
        if (g_groups_ready)
            return;

        invoke<void>(natives::ADD_RELATIONSHIP_GROUP, "VIOLET_BOTS", &g_group_bots);
        invoke<void>(natives::ADD_RELATIONSHIP_GROUP, "VIOLET_PLAYER", &g_group_player);

        // 0 = companion, 1 = respect, 2 = like, 3 = neutral, 4 = dislike,
        // 5 = hate. Bots always hate each other; the player relationship is
        // re-applied every tick from the config, so the toggle is live.
        invoke<void>(natives::SET_RELATIONSHIP_BETWEEN_GROUPS, 5, g_group_bots, g_group_bots);

        g_groups_ready = true;
        VIOLET_INFO("lobby: relationship groups registered");
    }

    void apply_relationships()
    {
        const int to_player = g_config.hostile_to_player.load() ? 5 : 3;
        invoke<void>(natives::SET_RELATIONSHIP_BETWEEN_GROUPS, to_player,
                     g_group_bots, g_group_player);
        invoke<void>(natives::SET_RELATIONSHIP_BETWEEN_GROUPS, to_player,
                     g_group_player, g_group_bots);

        const int to_each_other = g_config.fight_each_other.load() ? 5 : 3;
        invoke<void>(natives::SET_RELATIONSHIP_BETWEEN_GROUPS, to_each_other,
                     g_group_bots, g_group_bots);
    }

    // ---- model streaming ---------------------------------------------------
    //
    // A model must be resident before CREATE_PED will work. Requesting is
    // asynchronous, so we ask and give up for this frame if it is not ready -
    // blocking the script thread waiting for a load stalls the whole game.
    bool ensure_model(std::uint32_t model)
    {
        if (invoke<bool>(natives::HAS_MODEL_LOADED, model))
            return true;

        invoke<void>(natives::REQUEST_MODEL, model);
        return false;
    }

    Vector3 player_position(int player_ped)
    {
        return invoke<Vector3>(natives::GET_ENTITY_COORDS, player_ped, true);
    }

    void destroy_bot(Bot& bot)
    {
        if (bot.blip != 0)
        {
            invoke<void>(natives::REMOVE_BLIP, &bot.blip);
            bot.blip = 0;
        }

        if (bot.ped != 0)
        {
            // Mark it non-mission first, or DELETE_PED refuses.
            invoke<void>(natives::SET_ENTITY_AS_MISSION_ENTITY, bot.ped, true, true);
            invoke<void>(natives::DELETE_PED, &bot.ped);
            bot.ped = 0;
        }
    }

    bool spawn_bot(Bot& bot, int player_ped)
    {
        const char* model_name = k_models[next_random() % std::size(k_models)];
        const std::uint32_t model = hash_of(model_name);

        if (!ensure_model(model))
            return false;   // still streaming; try again next frame

        // Place them on a ring around the player, not on top of them.
        const Vector3 origin = player_position(player_ped);
        const float radius = g_config.spawn_radius.load();
        const float angle  = random_range(0.0f, 6.28318f);
        const float dist   = random_range(radius * 0.4f, radius);

        const float x = origin.x + std::cos(angle) * dist;
        const float y = origin.y + std::sin(angle) * dist;

        float ground = origin.z;
        invoke<bool>(natives::GET_GROUND_Z_FOR_3D_COORD, x, y, origin.z + 50.0f,
                     &ground, false);

        // CREATE_PED(pedType, model, x, y, z, heading, isNetwork, bScriptHostPed)
        // pedType 4 is a civmale; the engine largely ignores it for freemode
        // models but it must be a sane value.
        const int ped = invoke<int>(natives::CREATE_PED, 4, model,
                                    x, y, ground + 1.0f,
                                    random_range(0.0f, 360.0f), false, false);

        invoke<void>(natives::SET_MODEL_AS_NO_LONGER_NEEDED, model);

        if (ped == 0)
            return false;

        // Freemode models spawn with no clothing components at all. This gives
        // them the default outfit so they look like people rather than mannequins.
        invoke<void>(natives::SET_PED_DEFAULT_COMPONENT_VARIATION, ped);

        // Ours to manage, so the engine's population system will not quietly
        // delete them when you look away.
        invoke<void>(natives::SET_ENTITY_AS_MISSION_ENTITY, ped, true, true);

        invoke<void>(natives::SET_PED_RELATIONSHIP_GROUP_HASH, ped, g_group_bots);
        invoke<void>(natives::SET_PED_ACCURACY, ped, g_config.accuracy.load());
        invoke<void>(natives::SET_PED_ARMOUR, ped, 50);

        // Combat attributes worth setting, by index:
        //   0  can use cover
        //   1  can use vehicles
        //   2  can do drivebys
        //   5  always fight (never flee)
        //   46 always fight
        //   3  leave vehicle rather than cower
        for (const int attribute : { 0, 1, 2, 3, 5, 46 })
            invoke<void>(natives::SET_PED_COMBAT_ATTRIBUTES, ped, attribute, true);

        if (g_config.give_weapons.load())
        {
            const char* weapon = k_bot_weapons[next_random() % std::size(k_bot_weapons)];
            invoke<void>(natives::GIVE_WEAPON_TO_PED, ped, hash_of(weapon),
                         9999, false, true);
        }

        if (g_config.show_blips.load())
        {
            bot.blip = invoke<int>(natives::ADD_BLIP_FOR_ENTITY, ped);
            invoke<void>(natives::SET_BLIP_SPRITE, bot.blip, 1);   // plain dot
            invoke<void>(natives::SET_BLIP_COLOUR, bot.blip, 1);   // red
            invoke<void>(natives::SET_BLIP_SCALE,  bot.blip, 0.75f);
        }

        bot.ped         = ped;
        bot.name        = make_gamertag();
        bot.state       = BotState::Wander;
        bot.state_since = g_frame;
        bot.combat_target = 0;

        invoke<void>(natives::TASK_WANDER_STANDARD, ped, 10.0f, 10);
        return true;
    }

    void set_state(Bot& bot, BotState state)
    {
        if (bot.state == state)
            return;
        bot.state       = state;
        bot.state_since = g_frame;
    }

    float distance_between(const Vector3& a, const Vector3& b)
    {
        const float dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
        return std::sqrt(dx * dx + dy * dy + dz * dz);
    }

    // Decide what a bot should be doing, and only re-task when that changes.
    void update_behaviour(Bot& bot, int player_ped, const Vector3& player_pos)
    {
        const Vector3 pos = invoke<Vector3>(natives::GET_ENTITY_COORDS, bot.ped, true);
        const float to_player = distance_between(pos, player_pos);

        int target = 0;

        if (g_config.hostile_to_player.load() && to_player < 80.0f)
        {
            target = player_ped;
        }
        else if (g_config.fight_each_other.load())
        {
            // Nearest other living bot within range.
            float best = 60.0f;
            for (const auto& other : g_bots)
            {
                if (other.ped == 0 || other.ped == bot.ped || other.state == BotState::Dead)
                    continue;

                const Vector3 other_pos =
                    invoke<Vector3>(natives::GET_ENTITY_COORDS, other.ped, true);
                const float d = distance_between(pos, other_pos);
                if (d < best)
                {
                    best   = d;
                    target = other.ped;
                }
            }
        }

        if (target != 0)
        {
            // Only issue the task when the target actually changes. Re-issuing
            // TASK_COMBAT_PED every frame restarts it every frame, and the ped
            // stands there twitching instead of fighting.
            if (bot.state != BotState::Combat || bot.combat_target != target)
            {
                invoke<void>(natives::TASK_COMBAT_PED, bot.ped, target, 0, 16);
                bot.combat_target = target;
                set_state(bot, BotState::Combat);
            }
        }
        else if (bot.state != BotState::Wander)
        {
            invoke<void>(natives::TASK_WANDER_STANDARD, bot.ped, 10.0f, 10);
            bot.combat_target = 0;
            set_state(bot, BotState::Wander);
        }
    }

    void publish_snapshot(const Vector3& player_pos)
    {
        std::vector<BotView> view;
        view.reserve(g_bots.size());

        const bool want_tags = g_config.show_nametags.load();

        for (const auto& bot : g_bots)
        {
            BotView v;
            v.ped    = bot.ped;
            v.state  = bot.state;
            std::snprintf(v.name, sizeof(v.name), "%s", bot.name.c_str());

            if (bot.ped != 0 && bot.state != BotState::Dead)
            {
                const Vector3 pos =
                    invoke<Vector3>(natives::GET_ENTITY_COORDS, bot.ped, true);

                v.health   = invoke<int>(natives::GET_ENTITY_HEALTH, bot.ped);
                v.distance = distance_between(pos, player_pos);

                if (want_tags)
                {
                    // Ask the engine where this world point lands on screen.
                    // Doing the projection ourselves would mean finding the
                    // view matrix, which is exactly the kind of offset hunting
                    // this native saves us.
                    float sx = 0.0f, sy = 0.0f;
                    v.on_screen = invoke<bool>(natives::GET_SCREEN_COORD_FROM_WORLD_COORD,
                                               pos.x, pos.y, pos.z + 1.0f, &sx, &sy);
                    v.screen_x = sx;
                    v.screen_y = sy;
                }
            }

            view.push_back(v);
        }

        const std::scoped_lock lock{ g_snapshot_lock };
        g_snapshot.swap(view);
    }
}

// ---------------------------------------------------------------------------
// public
// ---------------------------------------------------------------------------

LobbyConfig& lobby_config() { return g_config; }

bool lobby_available()
{
    return natives::lobby_hashes_present() && scripthook_available();
}

const char* lobby_unavailable_reason()
{
    if (!natives::lobby_hashes_present())
        return "some native hashes for the lobby are not filled in yet";
    if (!scripthook_available())
        return "the native layer is unavailable";
    return "";
}

void lobby_shutdown()
{
    if (!natives::lobby_hashes_present())
        return;

    for (auto& bot : g_bots)
        destroy_bot(bot);

    g_bots.clear();

    const std::scoped_lock lock{ g_snapshot_lock };
    g_snapshot.clear();
}

std::size_t lobby_snapshot(BotView* out, std::size_t capacity)
{
    const std::scoped_lock lock{ g_snapshot_lock };

    const std::size_t count = (std::min)(capacity, g_snapshot.size());
    for (std::size_t i = 0; i < count; ++i)
        out[i] = g_snapshot[i];

    return count;
}

int lobby_alive_count()
{
    const std::scoped_lock lock{ g_snapshot_lock };
    return static_cast<int>(std::count_if(g_snapshot.begin(), g_snapshot.end(),
        [](const BotView& b) { return b.state != BotState::Dead && b.ped != 0; }));
}

int lobby_total_count()
{
    const std::scoped_lock lock{ g_snapshot_lock };
    return static_cast<int>(g_snapshot.size());
}

void lobby_tick()
{
    if (!natives::lobby_hashes_present())
        return;

    ++g_frame;

    if (g_config.want_clear.exchange(false))
    {
        lobby_shutdown();
        g_config.enabled = false;
        return;
    }

    if (!g_config.enabled.load())
    {
        if (!g_bots.empty())
            lobby_shutdown();
        return;
    }

    ensure_relationship_groups();
    apply_relationships();

    const int player_ped = invoke<int>(natives::PLAYER_PED_ID);
    if (player_ped == 0)
        return;

    invoke<void>(natives::SET_PED_RELATIONSHIP_GROUP_HASH, player_ped, g_group_player);

    const Vector3 player_pos = player_position(player_ped);

    if (g_config.want_respawn_all.exchange(false))
    {
        for (auto& bot : g_bots)
        {
            destroy_bot(bot);
            bot.state      = BotState::Dead;
            bot.respawn_at = g_frame;
        }
    }

    // ---- reap the dead ----
    for (auto& bot : g_bots)
    {
        if (bot.ped == 0 || bot.state == BotState::Dead)
            continue;

        const bool dead = invoke<bool>(natives::IS_ENTITY_DEAD, bot.ped);
        const Vector3 pos = invoke<Vector3>(natives::GET_ENTITY_COORDS, bot.ped, true);

        // Also retire anyone who has wandered far enough away to be irrelevant,
        // so the lobby stays around the player rather than smeared across the map.
        const bool too_far = distance_between(pos, player_pos) > 400.0f;

        if (dead || too_far)
        {
            destroy_bot(bot);
            set_state(bot, BotState::Dead);
            bot.respawn_at = g_frame + (dead ? 300u : 0u);   // ~5 s at 60 fps
        }
    }

    // ---- resize the roster ----
    const std::size_t desired = static_cast<std::size_t>(
        (std::max)(0, g_config.desired_bots.load()));

    while (g_bots.size() > desired)
    {
        destroy_bot(g_bots.back());
        g_bots.pop_back();
    }

    while (g_bots.size() < desired)
        g_bots.emplace_back();

    // ---- spawn and drive ----
    //
    // At most one spawn per frame. CREATE_PED plus its setup is not cheap, and
    // doing twenty in a single frame is a visible hitch.
    bool spawned_this_frame = false;

    for (auto& bot : g_bots)
    {
        if (bot.ped == 0 || bot.state == BotState::Dead)
        {
            if (!spawned_this_frame && g_frame >= bot.respawn_at)
            {
                if (spawn_bot(bot, player_ped))
                    spawned_this_frame = true;
            }
            continue;
        }

        update_behaviour(bot, player_ped, player_pos);
    }

    publish_snapshot(player_pos);
}
}
