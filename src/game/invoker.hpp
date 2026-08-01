#pragma once
//
// Violet - calling a native ourselves
//
// ---------------------------------------------------------------------------
// The call convention
// ---------------------------------------------------------------------------
//
// A native handler is not a normal function. It takes exactly one argument -
// a pointer to a call context - and reads its arguments out of that, writing
// any return value back into it:
//
//     void handler(scrNativeCallContext* ctx);
//
// The context, in the RAGE lineage:
//
//     +0x00  void*     return value storage
//     +0x08  uint32    argument count
//     +0x10  void*     argument storage
//     +0x18  uint32    data count
//
// We cannot read this off the disassembly - GTA's handlers are jump stubs into
// control-flow-obfuscated fragments, so there is nothing legible to inspect.
//
// So it gets verified the other way round: call a handler whose correct answer
// we can compute independently, and see whether the answer comes back right.
// GET_HASH_KEY is ideal for that - it is a pure function implementing Jenkins
// one-at-a-time, so if our context layout is wrong the result will not match,
// and if it is right the result cannot match by accident.
//
#include <cstdint>

namespace violet::game
{
    // GTA's string hash: Jenkins one-at-a-time, with the lowercase and
    // backslash normalisation visible in the game's own implementation.
    constexpr std::uint32_t joaat(const char* text)
    {
        std::uint32_t hash = 0;

        for (; *text != '\0'; ++text)
        {
            char c = *text;
            if (c >= 'A' && c <= 'Z') c += 32;
            else if (c == '\\')       c = '/';

            hash += static_cast<unsigned char>(c);
            hash += hash << 10;
            hash ^= hash >> 6;
        }

        hash += hash << 3;
        hash ^= hash >> 11;
        hash += hash << 15;
        return hash;
    }

    // Call a handler directly. Structured-exception guarded, because we are
    // invoking addresses recovered from an encrypted table in a live game and
    // a wrong guess must cost a failed call rather than the player's session.
    //
    // Returns false if the call faulted.
    bool call_handler_raw(std::uintptr_t handler,
                          const std::uint64_t* args,
                          std::uint32_t arg_count,
                          std::uint64_t& out_result);
}
