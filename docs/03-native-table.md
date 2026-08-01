# The native registration table — solved

**GTA V Enhanced `1.0.1158.13`.** Located, decoded, and verified from scratch: no
ScriptHookV, no published offsets, no borrowed signatures.

| | |
|---|---|
| Table RVA | **`0x3ED4C20`** (IDA `0x143ED4C20`) |
| Buckets | 256, indexed by `hash & 0xFF` |
| Block size | `0x100` bytes |
| Entries per block | 7 |
| Decoded | **6,748 natives across 1,076 blocks**, in ~200 ms |

---

## How it was found

Three approaches failed first, and each failure narrowed things usefully.

**The classic layout isn't there.** Searching `.data` for the historical RAGE structure
(`next` at `+0x00`, handlers at `+0x08`, count at `+0x40`) found a best 256-slot window
holding 29 valid blocks. A real table holds most of 256.

**The hashes are encrypted.** A sweep of all 7.6 GB of readable memory for two hashes
verified against the CitizenFX database returned two hits each — and *both were the
probe's own constants*, sitting in the DLL we had just injected. The bytes around them
decoded to `"GET_PLAY" "ER_PED"`. So the table can never be found by searching for a hash.

**There is no chain of raw code pointers.** Registration blocks form a linked list, which
is the one property a vtable can't imitate. Testing handler offsets `+0x08` through
`+0x20`, the longest chain anywhere was 2 blocks. (For contrast, the layout probe found
21,128 blocks with code-pointer runs at `+0x00` — ordinary C++ vtables, everywhere.)

**What did work** was searching for *runs of pointers into heap*, assuming nothing about
what they point at. That surfaced a run of exactly **256** entries whose blocks each held
a fixed seven-slot array of code pointers, zero-padded when unused — counts of 7, 3, 6 and
4 across four sampled buckets.

Then the memory dump — analysed by IDA into **134,608 functions**, versus ~10,500 from the
file on disk — made the rest mechanical. Grepping the disassembly for the table address
found this:

```asm
sub_140922F20   proc near
                lea     rsi, qword_143ED4C20      ; the table
                lea     r8,  qword_140920EA0      ; a handler
                mov     rdx, 4EDE34FBADD967A6h    ; a native hash
                mov     rcx, rsi
                call    sub_140920D70             ; registerNative(table, hash, handler)
```

`sub_140920D70` **is** the registration function — so it contains the obfuscation, written
out in full.

---

## The structure

```c
struct NativeRegistration          // 0x100 bytes
{
    u32  next_lo;                  // +0x00   ^ mask
    u32  next_hi;                  // +0x04   ^ mask      mask = (u32)block ^ next_key
    u32  next_key;                 // +0x08
    u32  _pad;                     // +0x0C

    void* handlers[7];             // +0x10   PLAINTEXT

    u32  count;                    // +0x48   ^ (u32)&count ^ count_key
    u32  count_key;                // +0x4C

    struct {                       // +0x54, stride 0x10
        u32 hash_lo;               //          ^ m
        u32 hash_hi;               //          ^ m    m = (u32)&hash_lo ^ key
        u32 key;
        u32 _pad;
    } hashes[7];

    u64  _unknown[7];              // +0xC8   zeroed at registration
};

static NativeRegistration* table[256];   // RVA 0x3ED4C20, indexed by hash & 0xFF
```

### Decoding

```c
next  = (block[0x00] ^ mask) | ((u64)(block[0x04] ^ mask) << 32);
        mask = (u32)block ^ block[0x08];

count = block[0x4C] ^ (u32)(block + 0x48) ^ block[0x48];

hash  = (f[0] ^ m) | ((u64)(f[1] ^ m) << 32);
        f = &block[0x54 + i*0x10];   m = (u32)f ^ f[2];

handler = block[0x10 + i*8];         // no decoding needed
```

### Why brute force could never have worked

Two reasons, and both matter.

**The next pointer is two 32-bit halves at `+0x00` and `+0x04`**, with the key at `+0x08`.
Every attempt treated `+0x00` and `+0x08` as whole 64-bit values, which is simply the
wrong shape.

**Every mask folds in the address of the field it protects** — `(u32)block` for the chain,
`(u32)&count` for the count, `(u32)&hash_lo` for each hash. So the mask differs for every
block, and for every entry within a block. No fixed formula, tried against any number of
samples, could have recovered it.

The keys themselves come from an LCG (`x * 0x343FD + 0x269EC3`) seeded from a global, and
are stored **right beside the values they hide**. Nothing needs breaking — only reading in
the right order.

### Why the handlers are plaintext

Encrypting them would mean decrypting on every native call, in the hottest path in the
scripting engine. Hashes are only touched at lookup; handlers are touched constantly. That
asymmetry is what made the table findable at all: we couldn't search for a hash, but seven
consecutive code pointers is unmistakable.

---

## Verification

Not "it produced a plausible number". The static disassembly assigns specific handlers to
specific hashes at their registration sites; the live decoder resolves the same hashes
independently. They agree exactly:

| Hash | Decoded RVA | Disassembly | |
|---|---|---|---|
| `0x4EDE34FBADD967A6` | `0x920EA0` | `0x920EA0` | ✅ |
| `0xE81651AD79516E48` | `0x921080` | `0x921080` | ✅ |
| `0xB8BA7F44DF1575E1` | `0x921290` | `0x921290` | ✅ |
| `0xEB1C67C3A5333A92` | `0x9214B0` | `0x9214B0` | ✅ |
| `0xC4BB298BD441BE78` | `0x9216D0` | `0x9216D0` | ✅ |

Two entirely separate methods — reading a 665 MB static disassembly, and walking encrypted
structures in a live process — landing on identical addresses.

Corroborating detail: every hash in bucket 0 ends in `0x00`, exactly as `hash & 0xFF`
requires.

---

## What this does and does not give you

**Does:** every one of the 6,748 natives this build registers, each with its current hash
and the address of the code implementing it, found without any external dependency.

**Does not:** a way to call a native *by name*.

Measured, not assumed. Checking 36 published hashes — the exact set Violet's features use —
against the decoded table:

```
  published-hash coverage on this build:
    WAIT                             RVA 0x920EA0

  1 of 36 published hashes resolve
```

**Enhanced re-hashed essentially every native.** `WAIT` survives because its hash never
changed. Nothing else does. And the reassignment is a lookup table, not a formula — there
is no arithmetic that turns a published hash into a 1158.13 one.

## What full independence would still require

1. **A native invoker.** Build `scrNativeCallContext` ourselves and call handlers directly.
   Derivable from the disassembly — a few hours.
2. **The script thread.** Natives are only safe on the game's script tick. Real RE, but
   findable now that the dump analyses properly.
3. **Name → handler, per native.** The blocker.

Point 3 has no bulk solution from first principles. A native's hash is only a lookup key —
what we actually need is its handler address — so a handler can in principle be identified
by *what its code does*. That works when the code is distinctive: GTA's string hash is
plainly visible in the disassembly as Jenkins one-at-a-time, complete with its lowercase
and backslash normalisation.

```asm
add  ebx, ebp          ; hash += c
shl  eax, 0Ah          ; hash += hash << 10
shr  ebp, 6            ; hash ^= hash >> 6
lea  ebp, [rbp+rbp*8]  ; hash += hash << 3
shr  eax, 0Bh          ; hash ^= hash >> 11
shl  edx, 0Fh          ; hash += hash << 15
```

But most natives are thin wrappers with nothing distinctive about them. `SET_ENTITY_HEALTH`
reads two arguments and writes a field; so do hundreds of others. Identifying ~40 of them
this way is ~40 separate reverse-engineering problems, and many have no unique fingerprint
at all.

### The bulk approach, tried and failed

Natives are registered in sequence, and `sub_140922F20` registers `WAIT` first — matching
`SYSTEM`'s canonical first entry. If registration order matched the published databases'
declaration order, zipping the two lists would recover all 6,748 names at once.

**It doesn't work.** The registration code is control-flow obfuscated.

Finding the real entry point was straightforward: `sub_140920D50(hash, handler)` is the
two-argument public form, which tail-jumps through a thunk that supplies the table and
lands in `sub_140920D70`. There are **6,667 calls to it across 45 registrar functions** —
and 45 is about the number of native namespaces, with the largest registrar holding 893
entries, consistent with `NETWORK` being the biggest namespace. The shape is right.

But the arguments are not set anywhere near their call:

```asm
loc_141BD3A25:
                call    sub_140920D50
                jmp     sub_1453347D4          ; flow continues elsewhere
; -------------------------------------------
                db 90h
                db 0FFh, 0C9h, 89h, 0CBh, 53h, 48h, 8Dh, 1Dh, 0C6h, 1Ch
```

Those bytes are `dec ecx / mov ebx,ecx / push rbx / lea rbx,[rip+…]` — real code IDA left
as data. Each registration is split into fragments stitched together by jumps and scattered
through the binary, so `mov rcx, <hash>` and `lea rdx, <handler>` are nowhere near the
`call` that consumes them.

An extractor requiring the operands within six lines of the call finds **zero** sites. A
loose one "finds" 6,667 — all reporting the same stale operand, which is the tell.

Only `sub_140922F20` is clean, and only because those 26 SYSTEM natives escaped the
obfuscation pass.

Recovering the order would mean following the control flow through the obfuscation or
emulating it, which is a substantially harder problem than decoding the table was.

---

## Bottom line

The reverse engineering of the table is **finished and verified**. What remains is not
reverse engineering — it is a naming problem that Rockstar deliberately scrambled twice
over: once by reassigning every hash, and again by obfuscating the code that would reveal
the mapping.
