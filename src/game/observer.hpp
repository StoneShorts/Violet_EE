#pragma once
//
// Violet - identifying natives by watching the game use them
//
// ---------------------------------------------------------------------------
// Why this, after the last attempt broke a session
// ---------------------------------------------------------------------------
//
// Calling unknown natives to see what they do killed a live game. Structured
// exception handling bounds a bad pointer; it does nothing about a function
// whose contract you do not know, and across thousands of them at least one
// tears the process down.
//
// So: stop calling, start watching.
//
// The registration table holds handler pointers as ordinary, writable memory,
// and we already decode it. Swapping an entry for a trampoline that logs the
// call and forwards it means the GAME still invokes the native - on its own
// thread, with its own arguments, at a moment it considers correct. We only
// observe. Nothing is invoked speculatively, so there is nothing to crash.
//
// What that buys is correlation. Watch normal gameplay and:
//
//   * a native called constantly with zero arguments, returning the same
//     non-zero value every time, is PLAYER_PED_ID
//   * a native called with THAT value, returning three floats that change as
//     you walk, is GET_ENTITY_COORDS
//
// Identification from observed behaviour, with the game as the witness.
//
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace violet::game
{
    struct Observation
    {
        std::uintptr_t handler   = 0;
        std::uint64_t  calls     = 0;
        std::uint32_t  arg_count = 0;   // as the game passed it
        std::uint64_t  first_arg = 0;
        std::uint64_t  last_result = 0;
        bool           result_stable = true;
    };

    // Redirect up to `limit` handlers through logging trampolines.
    // Returns how many were hooked.
    std::size_t observe_natives(const std::vector<std::uintptr_t>& handler_rvas,
                                std::size_t limit);

    // Put every original handler back. Safe to call if nothing was hooked, and
    // called automatically before the probe unloads - leaving trampolines in a
    // table that outlives our DLL would crash the game the moment it next used
    // one.
    void stop_observing();

    // Snapshot of what has been seen so far.
    std::vector<Observation> observations();

    std::size_t hooked_count();
}
