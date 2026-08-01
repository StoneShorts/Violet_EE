#include "game/observer.hpp"

#include "core/log.hpp"
#include "core/process.hpp"
#include "game/native_table.hpp"

#include <Windows.h>

#include <array>
#include <atomic>
#include <mutex>
#include <utility>

namespace violet::game
{
namespace
{
    // Must match the layout verified in game/invoker.cpp - and independently
    // confirmed by the GET_HASH_KEY handler reading its argument from [rcx+10h].
    struct NativeContextView
    {
        void*         return_storage;   // +0x00
        std::uint32_t arg_count;        // +0x08
        std::uint32_t _pad0;
        void*         arg_storage;      // +0x10
        std::uint32_t data_count;       // +0x18
        std::uint32_t _pad1;
    };

    using HandlerFn = void (*)(void*);

    constexpr std::size_t k_max_hooks = 512;

    struct Slot
    {
        std::atomic<HandlerFn>     original{ nullptr };
        std::uintptr_t             table_entry = 0;   // where the pointer lives
        std::atomic<std::uint64_t> calls{ 0 };
        std::atomic<std::uint32_t> arg_count{ 0 };
        std::atomic<std::uint64_t> first_arg{ 0 };
        std::atomic<std::uint64_t> last_result{ 0 };
        std::atomic<bool>          seen{ false };
        std::atomic<bool>          stable{ true };
    };

    Slot        g_slots[k_max_hooks];
    std::size_t g_hooked = 0;
    std::mutex  g_install_lock;

    // The trampoline body. Records what the game passed, forwards to the real
    // handler, then records what came back.
    //
    // Deliberately minimal: this runs on the game's script thread inside its
    // own frame budget, and anything expensive here would be felt as stutter.
    // No locks, no allocation, no logging - just atomics.
    void trampoline_body(std::size_t index, void* context)
    {
        Slot& slot = g_slots[index];

        const auto* view = static_cast<const NativeContextView*>(context);

        if (!slot.seen.exchange(true))
        {
            slot.arg_count = view->arg_count;
            if (view->arg_count > 0 && view->arg_storage != nullptr)
                slot.first_arg = *static_cast<const std::uint64_t*>(view->arg_storage);
        }

        slot.calls.fetch_add(1, std::memory_order_relaxed);

        HandlerFn original = slot.original.load(std::memory_order_acquire);
        if (original != nullptr)
            original(context);

        if (view->return_storage != nullptr)
        {
            const auto result = *static_cast<const std::uint64_t*>(view->return_storage);
            const auto previous = slot.last_result.exchange(result);
            if (previous != result && slot.calls.load() > 1)
                slot.stable = false;
        }
    }

    // A distinct function per slot, so each one knows which native it belongs
    // to without the game having to tell us. Generated at compile time rather
    // than by emitting machine code at runtime - same effect, none of the risk.
    template <std::size_t N>
    void trampoline(void* context) { trampoline_body(N, context); }

    template <std::size_t... Is>
    constexpr auto make_table(std::index_sequence<Is...>)
    {
        return std::array<HandlerFn, sizeof...(Is)>{ &trampoline<Is>... };
    }

    const auto g_trampolines = make_table(std::make_index_sequence<k_max_hooks>{});
}

std::size_t observe_natives(const std::vector<std::uintptr_t>& handler_rvas,
                            std::size_t limit)
{
    const std::scoped_lock lock{ g_install_lock };

    if (g_hooked != 0)
        return g_hooked;

    const auto info = violet::process::inspect(nullptr);
    if (!info)
        return 0;

    // decoded_natives() carries each entry's block and slot, which is exactly
    // where its handler pointer physically lives - so we can rewrite it.
    const auto& entries = decoded_natives();
    if (entries.empty())
        return 0;

    const std::size_t cap = (limit < k_max_hooks) ? limit : k_max_hooks;

    for (const auto rva : handler_rvas)
    {
        if (g_hooked >= cap)
            break;

        const std::uintptr_t handler = info->base + rva;

        for (const auto& e : entries)
        {
            if (e.handler != handler || e.block == 0)
                continue;

            // handlers[] sits at +0x10, eight bytes per slot.
            const std::uintptr_t entry_address = e.block + 0x10 + e.slot * 8;

            Slot& slot = g_slots[g_hooked];
            slot.table_entry = entry_address;
            slot.original.store(reinterpret_cast<HandlerFn>(handler),
                                std::memory_order_release);

            // A single aligned 8-byte store is atomic on x64, so the game
            // never sees a torn pointer even if it calls this native mid-swap.
            *reinterpret_cast<volatile std::uintptr_t*>(entry_address) =
                reinterpret_cast<std::uintptr_t>(g_trampolines[g_hooked]);

            ++g_hooked;
            break;
        }
    }

    VIOLET_INFO("observer: hooked {} native handler(s)", g_hooked);
    return g_hooked;
}

void stop_observing()
{
    const std::scoped_lock lock{ g_install_lock };

    for (std::size_t i = 0; i < g_hooked; ++i)
    {
        Slot& slot = g_slots[i];
        if (slot.table_entry == 0)
            continue;

        HandlerFn original = slot.original.load(std::memory_order_acquire);
        if (original != nullptr)
            *reinterpret_cast<volatile std::uintptr_t*>(slot.table_entry) =
                reinterpret_cast<std::uintptr_t>(original);

        slot.table_entry = 0;
    }

    if (g_hooked != 0)
        VIOLET_INFO("observer: restored {} handler(s)", g_hooked);

    g_hooked = 0;
}

std::vector<Observation> observations()
{
    std::vector<Observation> out;

    for (std::size_t i = 0; i < g_hooked; ++i)
    {
        const Slot& slot = g_slots[i];
        if (slot.calls.load() == 0)
            continue;

        Observation o;
        o.handler       = reinterpret_cast<std::uintptr_t>(
                              slot.original.load(std::memory_order_acquire));
        o.calls         = slot.calls.load();
        o.arg_count     = slot.arg_count.load();
        o.first_arg     = slot.first_arg.load();
        o.last_result   = slot.last_result.load();
        o.result_stable = slot.stable.load();
        out.push_back(o);
    }

    return out;
}

std::size_t hooked_count() { return g_hooked; }
}
