#pragma once
//
// Violet - the native layer
//
// ---------------------------------------------------------------------------
// Why this file exists, honestly
// ---------------------------------------------------------------------------
//
// Calling a native means turning a 64-bit hash into the address of the engine
// function implementing it, and then calling that function on a thread the
// engine considers safe. Violet spent a long time trying to do both from
// scratch. The findings are written up in docs/02-recon-findings.md, and they
// are real work - but they did not get as far as a working call:
//
//   * the native hashes are encrypted in memory (a sweep of all 7.6 GB found
//     only our own probe's constants)
//   * the registration blocks' chain pointer is obfuscated too, so the table
//     cannot be walked
//   * Enhanced is a Clang build of a newer engine, so no published offsets or
//     signatures from GTA V Legacy transfer
//
// So this borrows one component: ScriptHookV, which already solves exactly
// this and is maintained against each game build. Everything else in Violet -
// injection, the DirectComposition overlay, D3D12, the signature scanner, the
// memory dumper, the probe harness - remains ours.
//
// The from-scratch native layer is not abandoned; it is just not the thing
// standing between you and a working menu.
//
// ---------------------------------------------------------------------------
// Bound dynamically, never linked
// ---------------------------------------------------------------------------
//
// We resolve ScriptHookV's exports at runtime with GetProcAddress rather than
// linking its .lib. Three reasons:
//
//   1. Violet still builds and runs with no trace of it. Without ScriptHookV
//      present you get the overlay and every analysis tool, just no cheats.
//   2. Nothing third-party is vendored into the repository.
//   3. A static import that cannot be resolved stops the DLL loading AT ALL,
//      with an unhelpful error. Missing ScriptHookV should cost you features,
//      not the whole menu.
//
// Its exports are C++ symbols, so the names are mangled. Rather than hardcode
// mangled strings that would break if the signature ever changed, we walk the
// export table and match on the readable fragment inside ("nativeInit",
// "nativeCall", ...). That is both more robust and self-documenting - the log
// shows exactly what was found.
//
#include <cstdint>
#include <string>

namespace violet::game
{
    // Try to bind. Safe to call repeatedly - ScriptHookV may load after us.
    bool bind_scripthook();

    bool  scripthook_available();
    const std::string& scripthook_status();

    // ---- the script thread -------------------------------------------------
    //
    // Natives must be called from the game's script thread. Calling one from
    // our render thread reads engine state that is being mutated underneath us,
    // and it crashes - not always immediately, which is worse.
    //
    // ScriptHookV solves this: we hand it a function, it calls that function on
    // the correct thread every frame. Violet's features run there, and the UI
    // thread only ever sets flags for it to read.
    void start_script_thread(void* self_module);
    void stop_script_thread(void* self_module);

    // Has the script thread ticked? Until it has, no native has ever run.
    bool script_thread_alive();
    std::uint64_t script_tick_count();

    // ---- calling natives ---------------------------------------------------
    //
    // Only valid from inside the script thread callback.
    void native_init(std::uint64_t hash);
    void native_push(std::uint64_t value);
    std::uint64_t* native_call();
}
