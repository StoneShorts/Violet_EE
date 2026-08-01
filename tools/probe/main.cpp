//
// probe.dll - run an analysis pass inside the game and leave again
//
// This exists so investigation does not require the whole menu.
//
// Violet may already be injected and running its overlay; injecting a second
// copy would give you two windows fighting over the same hotkeys and two
// writers truncating the same log. The probe instead carries only the analysis
// code: no window, no D3D12, no ImGui, no hotkeys. It runs one pass, writes its
// findings to its own log file, and unloads itself.
//
// That makes it safe to fire at a live session repeatedly while iterating on
// what we are looking for.
//
#include "core/log.hpp"
#include "core/process.hpp"
#include "game/invoker.hpp"
#include "game/native_table.hpp"

#include <Windows.h>

#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace
{
    HMODULE g_self = nullptr;

    DWORD WINAPI probe_main(LPVOID)
    {
        // Its own log, and deliberately no console - popping one over someone's
        // running game is rude.
        violet::log::init(g_self, /*also_open_console=*/ false, L"Violet_probe.log");

        VIOLET_INFO("========================================");
        VIOLET_INFO(" Violet probe - native table hunt");
        VIOLET_INFO("========================================");

        wchar_t host[MAX_PATH]{};
        GetModuleFileNameW(nullptr, host, MAX_PATH);
        VIOLET_INFO("host : {}", std::filesystem::path{ host }.filename().string());
        VIOLET_INFO("pid  : {}", GetCurrentProcessId());

        if (const auto info = violet::process::inspect(nullptr))
        {
            VIOLET_INFO("base : 0x{:X}   preferred 0x{:X}", info->base, info->preferred_base);
            VIOLET_INFO("");
        }

        const auto scan = violet::game::find_native_table();

        VIOLET_INFO("--- result -----------------------------------------");
        VIOLET_INFO("  took      : {:.0f} ms", scan.elapsed_ms);
        VIOLET_INFO("  found     : {}", scan.found ? "YES" : "no");
        VIOLET_INFO("  detail    : {}", scan.detail);

        if (scan.table != 0)
        {
            VIOLET_INFO("  table     : 0x{:X}", scan.table);
            VIOLET_INFO("  table RVA : 0x{:X}   (IDA 0x{:X})",
                        scan.table_rva, 0x140000000ull + scan.table_rva);
            VIOLET_INFO("  slots     : {} of 256", scan.slots);
            VIOLET_INFO("  blocks    : {}", scan.blocks);
            VIOLET_INFO("  natives   : {}", scan.natives);

            for (const auto& s : scan.samples)
                VIOLET_INFO("    hash 0x{:016X}  ->  handler 0x{:X}", s.hash, s.handler);
        }

        // Hashes are not stored in plaintext (established by hunt_known_hashes
        // on an earlier run - the only matches were the probe's own constants).
        // So the table has to be found structurally.
        // The real decode, using the layout read out of GTA's own
        // registerNative(). Located automatically rather than hardcoded.
        VIOLET_INFO("");
        VIOLET_INFO("--- decoding the native table ----------------------");
        {
            const auto decoded = violet::game::decode_native_table();

            VIOLET_INFO("  took      : {:.0f} ms", decoded.elapsed_ms);
            VIOLET_INFO("  result    : {}", decoded.ok ? "SUCCESS" : "failed");
            VIOLET_INFO("  detail    : {}", decoded.detail);

            if (decoded.table != 0)
            {
                VIOLET_INFO("  table     : 0x{:X}", decoded.table);
                VIOLET_INFO("  table RVA : 0x{:X}   (IDA 0x{:X})",
                            decoded.table_rva, 0x140000000ull + decoded.table_rva);
            }

            // ---- self-verification against the static disassembly ----
            //
            // These pairs were read out of sub_140922F20 in the memory dump,
            // where the game registers natives with literal hashes:
            //
            //     lea  r8,  qword_140920EA0
            //     mov  rdx, 4EDE34FBADD967A6h
            //     call sub_140920D70
            //
            // If the live decode resolves each hash to the same RVA the static
            // disassembly assigns it, the decode is correct - independently
            // confirmed by two entirely separate methods.
            struct Check { std::uint64_t hash; std::uintptr_t expect_rva; };
            constexpr Check checks[] = {
                { 0x4EDE34FBADD967A6ull, 0x920EA0 },
                { 0xE81651AD79516E48ull, 0x921080 },
                { 0xB8BA7F44DF1575E1ull, 0x921290 },
                { 0xEB1C67C3A5333A92ull, 0x9214B0 },
                { 0xC4BB298BD441BE78ull, 0x9216D0 },
            };

            const auto module_info = violet::process::inspect(nullptr);
            const std::uintptr_t base = module_info ? module_info->base : 0;

            VIOLET_INFO("");
            VIOLET_INFO("  cross-check against the static disassembly:");

            int matched = 0;
            for (const auto& c : checks)
            {
                const auto handler = violet::game::find_native_handler(c.hash);
                const auto rva = (handler && base) ? handler - base : 0;
                const bool ok = rva == c.expect_rva;
                matched += ok ? 1 : 0;

                VIOLET_INFO("    0x{:016X} -> RVA 0x{:<8X} expected 0x{:<8X}  {}",
                            c.hash, rva, c.expect_rva, ok ? "MATCH" : "mismatch");
            }

            VIOLET_INFO("");
            if (matched == static_cast<int>(std::size(checks)))
                VIOLET_INFO("  *** {}/{} match - the decode is CORRECT ***",
                            matched, std::size(checks));
            else
                VIOLET_WARN("  only {}/{} matched", matched, std::size(checks));

            // ---- coverage: do the published hashes work on this build? ----
            //
            // This decides whether the ScriptHookV dependency can go away. If
            // the hashes Violet already uses are present in the table we
            // decoded ourselves, we can resolve handlers directly. If they are
            // absent, this build re-hashed its natives and we would need a
            // translation for 1158.13 before calling anything by name.
            struct Named { const char* name; std::uint64_t hash; };
            constexpr Named published[] = {
                { "WAIT",                        0x4EDE34FBADD967A6ull },
                { "PLAYER_PED_ID",               0xD80958FC74E988A6ull },
                { "PLAYER_ID",                   0x4F8644AF03D0E0D6ull },
                { "GET_PLAYER_PED",              0x43A66C31C68491C0ull },
                { "GET_HASH_KEY",                0xD24D37CC275948CCull },
                { "SET_ENTITY_INVINCIBLE",       0x3882114BDE571AD4ull },
                { "SET_ENTITY_HEALTH",           0x6B76DC1F3AE6E6A3ull },
                { "GET_ENTITY_HEALTH",           0xEEF059FAD016D209ull },
                { "GET_ENTITY_MAX_HEALTH",       0x15D757606D170C3Cull },
                { "SET_PED_ARMOUR",              0xCEA04D83135264CCull },
                { "SET_PLAYER_WANTED_LEVEL",     0x39FF19C64EF7DA5Bull },
                { "SET_PLAYER_WANTED_LEVEL_NOW", 0xE0A7D1E497FFCD6Full },
                { "GIVE_WEAPON_TO_PED",          0xBF0FD6E56C964FCBull },
                { "SET_PED_INFINITE_AMMO_CLIP",  0x183DADC6AA953186ull },
                { "SET_ENTITY_COORDS",           0x06843DA7060A026Bull },
                { "GET_ENTITY_COORDS",           0x3FEF770D40960D5Aull },
                { "GET_GROUND_Z_FOR_3D_COORD",   0xC906A7DAB05C8D2Bull },
                { "GET_VEHICLE_PED_IS_IN",       0x9A9112A0FE9A4713ull },
                { "IS_WAYPOINT_ACTIVE",          0x1DD1F58F493F1DA5ull },
                { "GET_FIRST_BLIP_INFO_ID",      0x1BEDE233E6CD2A1Full },
                { "GET_BLIP_INFO_ID_COORD",      0xFA7C7F0AADF25D09ull },
                { "SET_CLOCK_TIME",              0x47C3B5848C3E45D8ull },
                { "CREATE_PED",                  0xD49F9B0955C367DEull },
                { "DELETE_PED",                  0x9614299DCB53E54Bull },
                { "REQUEST_MODEL",               0x963D27A58DF860ACull },
                { "HAS_MODEL_LOADED",            0x98A4EB5D89A0C952ull },
                { "TASK_WANDER_STANDARD",        0xBB9CE077274F6A1Bull },
                { "TASK_COMBAT_PED",             0xF166E48407BAC484ull },
                { "SET_PED_ACCURACY",            0x7AEFB85C1D49DEB6ull },
                { "SET_PED_COMBAT_ATTRIBUTES",   0x9F7794730795E019ull },
                { "ADD_RELATIONSHIP_GROUP",      0xF372BC22FCB88606ull },
                { "ADD_BLIP_FOR_ENTITY",         0x5CDE92C702A8FCE7ull },
                { "SET_BLIP_SPRITE",             0xDF735600A4696DAFull },
                { "REMOVE_BLIP",                 0x86A652570E5F25DDull },
                { "IS_ENTITY_DEAD",              0x5F9532F3B5CC2551ull },
                { "SET_ENTITY_AS_MISSION_ENTITY",0xAD738C3085FE7E11ull },
            };

            VIOLET_INFO("");
            VIOLET_INFO("  published-hash coverage on this build:");

            int present = 0;
            for (const auto& n : published)
            {
                const auto handler = violet::game::find_native_handler(n.hash);
                if (handler != 0)
                {
                    ++present;
                    VIOLET_INFO("    {:<32} RVA 0x{:X}", n.name,
                                base ? handler - base : 0);
                }
            }

            VIOLET_INFO("");
            VIOLET_INFO("  {} of {} published hashes resolve",
                        present, std::size(published));

            if (present == static_cast<int>(std::size(published)))
                VIOLET_INFO("  -> all of them. ScriptHookV is not needed for lookups.");
            else if (present == 0)
                VIOLET_WARN("  -> none. This build re-hashed its natives entirely.");
            else
                VIOLET_WARN("  -> partial. Some natives were re-hashed on this build.");

            // Dump the whole decoded table to disk.
            //
            // 6748 rows of (hash, RVA) is the raw material for everything else:
            // intersecting it with the disassembly is how a handler gets
            // identified by what its code does, rather than by a name we do
            // not have.
            const auto& all = violet::game::decoded_natives();
            {
                wchar_t* local = nullptr;
                std::size_t len = 0;
                if (_wdupenv_s(&local, &len, L"LOCALAPPDATA") == 0 && local)
                {
                    const std::filesystem::path out =
                        std::filesystem::path{ local } / L"Violet" / L"natives.tsv";
                    std::free(local);

                    std::ofstream f{ out, std::ios::trunc };
                    if (f)
                    {
                        f << "hash\trva\tblock\tslot\n";
                        for (const auto& e : all)
                            f << std::format("{:016X}\t{:X}\t{:X}\t{}\n",
                                             e.hash, base ? e.handler - base : 0,
                                             e.block, e.slot);
                        VIOLET_INFO("");
                        VIOLET_INFO("  wrote {} rows to {}", all.size(), out.string());
                    }
                }
            }
        }

        // ---- calling a native ourselves ----------------------------------
        //
        // The decisive test. Candidates were narrowed statically: native
        // handlers that call GTA's joaat routine, ranked by how small their
        // real body is. GET_HASH_KEY should be among the smallest, because it
        // does nothing but hash.
        //
        // We call each with the string "WEAPON_PISTOL" and compare against a
        // joaat we compute ourselves. A wrong call-context layout cannot
        // produce the right answer, and the right answer cannot occur by
        // accident - so a match verifies the invoker AND identifies the native
        // in one shot.
        {
            VIOLET_INFO("");
            VIOLET_INFO("--- calling natives from scratch -------------------");

            const auto module_info2 = violet::process::inspect(nullptr);
            const std::uintptr_t mbase = module_info2 ? module_info2->base : 0;

            constexpr const char* k_probe_string = "WEAPON_PISTOL";
            const std::uint32_t expected = violet::game::joaat(k_probe_string);

            VIOLET_INFO("  test string : \"{}\"", k_probe_string);
            VIOLET_INFO("  expected    : 0x{:08X}  (joaat, computed by us)", expected);
            VIOLET_INFO("");

            std::vector<std::uintptr_t> candidates;
            {
                wchar_t* local = nullptr;
                std::size_t len = 0;
                if (_wdupenv_s(&local, &len, L"LOCALAPPDATA") == 0 && local)
                {
                    const std::filesystem::path list =
                        std::filesystem::path{ local } / L"Violet" / L"candidates.txt";
                    std::free(local);

                    std::ifstream f{ list };
                    std::string line;
                    while (std::getline(f, line))
                    {
                        if (line.empty()) continue;
                        candidates.push_back(std::strtoull(line.c_str(), nullptr, 16));
                    }
                }
            }

            VIOLET_INFO("  {} candidate handler(s) to try", candidates.size());

            const std::uint64_t args[1] = {
                reinterpret_cast<std::uint64_t>(k_probe_string)
            };

            bool found = false;
            for (const auto rva : candidates)
            {
                const std::uintptr_t handler = mbase + rva;

                std::uint64_t result = 0;
                const bool ok = violet::game::call_handler_raw(handler, args, 1, result);

                const auto low = static_cast<std::uint32_t>(result);
                const bool match = ok && low == expected;

                VIOLET_INFO("    RVA 0x{:<8X} {}  returned 0x{:08X}  {}",
                            rva, ok ? "called " : "FAULTED", low,
                            match ? "*** MATCH ***" : "");

                if (match)
                {
                    found = true;

                    // Reverse-look-up its hash in the table we decoded, giving
                    // GET_HASH_KEY's real hash on this build.
                    for (const auto& e : violet::game::decoded_natives())
                    {
                        if (e.handler == handler)
                        {
                            VIOLET_INFO("");
                            VIOLET_INFO("  GET_HASH_KEY on build 1158.13:");
                            VIOLET_INFO("    hash    0x{:016X}", e.hash);
                            VIOLET_INFO("    handler RVA 0x{:X}", rva);
                            break;
                        }
                    }
                    break;
                }
            }

            VIOLET_INFO("");
            if (found)
            {
                VIOLET_INFO("  *** A NATIVE WAS CALLED FROM SCRATCH AND RETURNED");
                VIOLET_INFO("      THE CORRECT ANSWER. No ScriptHookV involved. ***");
            }
            else
            {
                VIOLET_WARN("  no candidate produced the expected hash");
            }
        }

        // ---- identify the SYSTEM math natives by calling them -------------
        //
        // SYSTEM is the one namespace whose registrar escaped the control-flow
        // obfuscation, so its 25 handlers were readable straight out of the
        // disassembly in registration order. Nearly all of them are pure maths.
        //
        // Rather than assume an ordering, each is identified by BEHAVIOUR: call
        // it with inputs whose answer we know and see which one produces it.
        // That is proof rather than inference, and it exercises the invoker
        // across int arguments, float arguments and multi-argument calls.
        //
        // Indices 0-9 are deliberately skipped: WAIT yields the thread, and the
        // script-start and timer natives have side effects.
        {
            VIOLET_INFO("");
            VIOLET_INFO("--- identifying SYSTEM natives by behaviour --------");

            const auto mi = violet::process::inspect(nullptr);
            const std::uintptr_t mbase = mi ? mi->base : 0;

            constexpr std::uintptr_t k_system[] = {
                0x923290, 0x9232C0, 0x9232F0, 0x923330, 0x923360, 0x923390,
                0x9233E0, 0x923410, 0x923470, 0x9234B0, 0x9234D0, 0x9234F0,
                0x923510, 0x923530, 0x923550,
            };

            const auto as_bits = [](float f)
            {
                std::uint32_t b = 0;
                std::memcpy(&b, &f, 4);
                return static_cast<std::uint64_t>(b);
            };
            const auto as_float = [](std::uint64_t v)
            {
                const auto b = static_cast<std::uint32_t>(v);
                float f = 0.0f;
                std::memcpy(&f, &b, 4);
                return f;
            };
            // Not called "near" - windows.h still #defines that from the
            // 16-bit era, and it turns the declaration into a syntax error.
            const auto close_enough = [](float a, float b)
            {
                const float d = a - b;
                return (d < 0.05f && d > -0.05f);
            };

            struct Test
            {
                const char*   name;
                std::uint32_t argc;
                std::uint64_t args[6];
                bool          float_result;
                float         expect_f;
                std::int32_t  expect_i;
            };

            const Test tests[] = {
                { "SQRT(16) = 4",           1, { as_bits(16.0f) },                       true,  4.0f,    0 },
                { "POW(2,10) = 1024",       2, { as_bits(2.0f), as_bits(10.0f) },        true,  1024.0f, 0 },
                { "FLOOR(3.7) = 3",         1, { as_bits(3.7f) },                        false, 0.0f,    3 },
                { "CEIL(3.2) = 4",          1, { as_bits(3.2f) },                        false, 0.0f,    4 },
                { "ROUND(3.6) = 4",         1, { as_bits(3.6f) },                        false, 0.0f,    4 },
                { "TO_FLOAT(7) = 7.0",      1, { 7ull },                                 true,  7.0f,    0 },
                { "SHIFT_LEFT(1,4) = 16",   2, { 1ull, 4ull },                           false, 0.0f,    16 },
                { "SHIFT_RIGHT(256,4)= 16", 2, { 256ull, 4ull },                         false, 0.0f,    16 },
                { "VDIST(0,0,0,3,4,0)= 5",  6, { as_bits(0), as_bits(0), as_bits(0),
                                                 as_bits(3.0f), as_bits(4.0f), as_bits(0) },
                                                                                          true,  5.0f,    0 },
            };

            int identified = 0;
            for (const auto& t : tests)
            {
                for (const auto rva : k_system)
                {
                    std::uint64_t r = 0;
                    if (!violet::game::call_handler_raw(mbase + rva, t.args, t.argc, r))
                        continue;

                    const bool hit = t.float_result
                        ? close_enough(as_float(r), t.expect_f)
                        : (static_cast<std::int32_t>(r) == t.expect_i);

                    if (hit)
                    {
                        VIOLET_INFO("    {:<24} -> RVA 0x{:X}", t.name, rva);
                        ++identified;
                        break;
                    }
                }
            }

            VIOLET_INFO("");
            VIOLET_INFO("  {} of {} identified purely by calling them",
                        identified, std::size(tests));
        }

        // ---- hunting PLAYER_PED_ID ----------------------------------------
        //
        // DISABLED. This crashed a live game and the approach is not safe.
        //
        // The idea was sound in outline: narrow to handlers that never read
        // [rcx+10h] (and so take no arguments), call each twice, and look for
        // one returning a stable non-zero handle. PLAYER_PED_ID is the gateway
        // native - with the player's ped handle in hand, most other natives
        // become testable by observing their effect on a known entity.
        //
        // What it got wrong is the safety model. Structured exception handling
        // catches an access violation, which made "call it and see" feel safe.
        // It does not catch a native that fast-fails, tears down the process,
        // or corrupts engine state badly enough that the game dies moments
        // later. Across ~2000 unknown natives at least one does exactly that:
        // the run died within the first few calls, before recording anything.
        //
        // The lesson is that SEH bounds the blast radius of a BAD POINTER, not
        // of an unknown FUNCTION. Calling code whose contract you do not know
        // is not made safe by wrapping it in a try block.
        //
        // A safe version needs candidates narrowed to near-certainty before any
        // call happens - as GET_HASH_KEY was, by finding the joaat algorithm
        // statically first, so that only a handful of calls were ever needed.
        // Blind sweeps over thousands of unknown functions are out.
        constexpr bool k_enable_blind_sweep = false;

        if constexpr (k_enable_blind_sweep)
        {
            VIOLET_INFO("");
            VIOLET_INFO("--- hunting PLAYER_PED_ID -------------------------");

            const auto mi = violet::process::inspect(nullptr);
            const std::uintptr_t mbase = mi ? mi->base : 0;

            std::vector<std::uintptr_t> zero_arg;
            {
                wchar_t* local = nullptr;
                std::size_t len = 0;
                if (_wdupenv_s(&local, &len, L"LOCALAPPDATA") == 0 && local)
                {
                    const std::filesystem::path p =
                        std::filesystem::path{ local } / L"Violet" / L"zeroarg.txt";
                    std::free(local);

                    std::ifstream f{ p };
                    std::string line;
                    while (std::getline(f, line))
                        if (!line.empty())
                            zero_arg.push_back(std::strtoull(line.c_str(), nullptr, 16));
                }
            }

            VIOLET_INFO("  {} zero-argument candidates", zero_arg.size());

            std::size_t called = 0, faulted = 0, nonzero = 0, stable = 0;
            std::vector<std::pair<std::uintptr_t, std::uint64_t>> hits;

            for (const auto rva : zero_arg)
            {
                std::uint64_t a = 0, b = 0;
                const bool ok1 = violet::game::call_handler_raw(mbase + rva, nullptr, 0, a);
                if (!ok1) { ++faulted; continue; }
                ++called;

                if (a == 0) continue;
                ++nonzero;

                const bool ok2 = violet::game::call_handler_raw(mbase + rva, nullptr, 0, b);
                if (!ok2 || a != b) continue;
                ++stable;

                // A ped handle is a modest positive integer. Anything huge is a
                // pointer or a timer, not an entity handle.
                if (a < 0x10000000ull)
                    hits.emplace_back(rva, a);
            }

            VIOLET_INFO("  called {}, faulted {}, non-zero {}, stable {}",
                        called, faulted, nonzero, stable);
            VIOLET_INFO("  handle-shaped stable results: {}", hits.size());

            // Group by value: the player's ped handle should be returned by
            // more than one native, which is a strong corroborating signal.
            std::map<std::uint64_t, std::vector<std::uintptr_t>> by_value;
            for (const auto& [rva, v] : hits)
                by_value[v].push_back(rva);

            for (const auto& [value, rvas] : by_value)
            {
                if (rvas.size() < 2 && by_value.size() > 12)
                    continue;

                std::string list;
                for (std::size_t i = 0; i < rvas.size() && i < 6; ++i)
                    list += std::format("0x{:X} ", rvas[i]);

                VIOLET_INFO("    value {:<10} returned by {} native(s): {}",
                            value, rvas.size(), list);
            }
        }

        VIOLET_INFO("");
        VIOLET_INFO("probe complete - unloading");
        violet::log::shutdown();

        FreeLibraryAndExitThread(g_self, 0);
    }
}

BOOL APIENTRY DllMain(HMODULE self, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = self;
        DisableThreadLibraryCalls(self);

        if (const HANDLE t = CreateThread(nullptr, 0, probe_main, nullptr, 0, nullptr))
            CloseHandle(t);
    }
    return TRUE;
}
