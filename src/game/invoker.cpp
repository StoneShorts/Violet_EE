#include "game/invoker.hpp"

#include <Windows.h>

#include <cstring>

namespace violet::game
{
namespace
{
    // scrNativeCallContext. 16-byte aligned because the engine moves values
    // through it with SSE loads and stores.
    struct alignas(16) NativeContext
    {
        void*         return_storage = nullptr;   // +0x00
        std::uint32_t arg_count      = 0;         // +0x08
        std::uint32_t _pad0          = 0;         // +0x0C
        void*         arg_storage    = nullptr;   // +0x10
        std::uint32_t data_count     = 0;         // +0x18
        std::uint32_t _pad1          = 0;         // +0x1C

        // Generous, and zeroed. A native expecting more arguments than we
        // supply reads zeroes rather than whatever happened to be on the stack,
        // which is the difference between "returns nothing useful" and
        // "dereferences garbage".
        std::uint64_t args[32]{};
        std::uint64_t returns[4]{};
    };

    using HandlerFn = void (*)(NativeContext*);

    // The call itself, isolated in its own function because a routine using
    // __try may not hold C++ objects that need unwinding.
    bool guarded_call(HandlerFn handler, NativeContext* context)
    {
        __try
        {
            handler(context);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }
}

bool call_handler_raw(std::uintptr_t handler,
                      const std::uint64_t* args,
                      std::uint32_t arg_count,
                      std::uint64_t& out_result)
{
    out_result = 0;

    if (handler == 0 || arg_count > 32)
        return false;

    NativeContext context{};
    context.arg_count      = arg_count;
    context.data_count     = arg_count;
    context.arg_storage    = context.args;
    context.return_storage = context.returns;

    for (std::uint32_t i = 0; i < arg_count; ++i)
        context.args[i] = args[i];

    if (!guarded_call(reinterpret_cast<HandlerFn>(handler), &context))
        return false;

    out_result = context.returns[0];
    return true;
}
}
