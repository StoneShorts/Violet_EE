# Stage 2 recon — GTA5_Enhanced.exe 1.0.1158.13

First successful injection into the live game. Captured 2026-07-31.

| | |
|---|---|
| Host | `GTA5_Enhanced.exe`, pid 29492 |
| Runtime base | `0x7FF7D29B0000` *(per-boot — do not write this down)* |
| **Preferred base** | **`0x140000000`** *(what IDA shows)* |
| Slide, that session | `+0x7FF6929B0000` |
| SizeOfImage | `0x5B81000` — 91.5 MB |
| Loaded modules | 179 |
| BattlEye | **absent** ✅ |

> Runtime addresses are only valid for one boot. **RVAs are the durable form.**
> `runtime = base + RVA` · `IDA = 0x140000000 + RVA`

---

## Section map

| # | Name | RVA | IDA address | Size | Flags |
|---|---|---|---|---|---|
| 0 | `.text` | `0x1000` | `0x140001000` | 38,245,376 | R-X |
| 1 | `.rdata` | `0x247B000` | `0x14247B000` | 4,124,160 | R-- |
| 2 | `.data` | `0x286A000` | `0x14286A000` | 41,161,768 | RW- |
| 3 | `.pdata` | `0x4FAC000` | `0x144FAC000` | 869,376 | R-- |
| 4 | `.00cfg` | `0x5081000` | `0x145081000` | 512 | R-- |
| 5 | `.retplne` | `0x5082000` | `0x145082000` | 512 | --- |
| 6 | `.tls` | `0x5083000` | `0x145083000` | 89,600 | RW- |
| 7 | `.voltbl` | `0x5099000` | `0x145099000` | 512 | --- |
| 8 | `.xbld` | `0x509A000` | `0x14509A000` | 512 | RW- |
| 9 | `.rsrc` | `0x509B000` | `0x14509B000` | 188,928 | R-- |
| 10 | `.reloc` | `0x50CA000` | `0x1450CA000` | 331,776 | R-- |
| 11 | `.xbld` | `0x511B000` | `0x14511B000` | 512 | RW- |
| 12 | `.idata` | `0x511C000` | `0x14511C000` | 27,136 | RW- |
| 13 | **`.text`** | `0x5123000` | `0x145123000` | 10,870,784 | R-X |

### Finding 1 — two `.text` sections

**46.8 MB of executable code across two sections**, not one:

* `.text` #0 — 36.5 MB at RVA `0x1000`
* `.text` #13 — 10.4 MB at RVA `0x5123000`

The stage 5 scanner must sweep **both**. Searching only "the section named `.text`"
finds the first and silently misses 22% of the code — a pattern that legitimately
exists would simply come back not-found, with nothing to indicate why.

Fixed in `process.cpp`: `executable_sections()` replaces `find_section(".text")`.

### Finding 2 — the binary was rewritten after linking

Three things say so:

1. Sections `.xbld`, `.idata` and `.text` all appear **after `.reloc`**. A stock MSVC
   link puts `.reloc` last.
2. **Duplicate section names** — `.text` twice, `.xbld` twice. MSVC merges same-named
   sections by default, so two survivors means something else emitted them.
3. `.idata` exists as a **separate writable section**. Modern MSVC folds the import
   directory into `.rdata`.

GTA has historically shipped with commercial anti-tamper, and this is the shape it
leaves behind.

**Why it matters:** if a protector decrypts or rebuilds code at runtime, then the
bytes IDA reads from disk are not the bytes the CPU executes, and patterns derived
statically won't match memory. Before trusting IDA we should verify by **diffing the
on-disk `.text` against the in-memory `.text`**. If they largely agree, IDA is
trustworthy and static analysis is fine. If they diverge in bulk, we dump the module
from memory and analyse that instead.

Expect *some* legitimate difference either way — the loader applies base relocations
from `.reloc`, and the overlay DLLs below have hot-patched functions. Small scattered
deltas are normal; large contiguous regions are not.

### Finding 3 — `.data` is 39 MB

Unusually large, and where the engine's globals live: the world pointer, entity pools,
replay interface, script globals. Stage 5's second half will spend its time here.

---

## Modules of interest

### Already hooking Present — resolve before stage 3

| Module | Source | How to disable |
|---|---|---|
| `nvspcap64.dll` | NVIDIA ShadowPlay / overlay | NVIDIA App → Settings → **In-Game Overlay** off |
| `NvCamera64.dll` | NVIDIA Ansel photo mode | Same toggle |
| `DiscordHook64.dll` | Discord overlay | Discord → Settings → Game Overlay → off for GTA |
| `SocialClubD3D12Renderer.dll` | Rockstar's own overlay | Can't remove — must coexist |

Every one of these has already installed itself in the swapchain. Adding a fifth hook
in an undefined order is the standard cause of DX12 overlay crashes. Turn off the
first three; Rockstar's own we simply have to live alongside.

### Graphics stack

* `d3d12.dll` + **`D3D12Core.dll`** — the game ships the **DirectX Agility SDK**
  (hence the `D3D12-REDIST\` folder) rather than relying on the OS runtime.
* `dxgi.dll` — swapchain lives here; `IDXGISwapChain3::Present1` is our stage 3 target.
* `d3d11.dll` also loaded — normal, D3D11On12 is commonly used for UI/text.
* `nvngx_dlss.dll`, `nvngx_dlssg.dll` — DLSS + frame generation.

> **Frame generation is worth flagging now.** DLSS-G inserts generated frames into the
> present chain. Overlays that hook Present naively either render on generated frames
> they shouldn't, or flicker. If Violet's overlay misbehaves later, turning frame gen
> off is the first thing to test.

---

---

## What the build path tells us

Rockstar left the PDB path in the binary. IDA shows it in the file header:

```
X:\gta5\titleupdate\dev_gen9_sga_live\game_win64_gdk_master_llvm.pdb
```

| Fragment | Meaning |
|---|---|
| `dev_gen9` | 9th-gen console codebase — the Enhanced branch, not Legacy |
| `sga` | Rockstar's internal name for this engine variant. **The game's window class is `sgaWindow`** — same name |
| `gdk` | built against Microsoft's Game Development Kit |
| **`llvm`** | **compiled with Clang/LLVM, not MSVC** |

That last one has real consequences. Every published signature for GTA V Legacy was
derived from an **MSVC** build. Clang emits different prologues, different register
allocation, different inlining and different idioms for the same source. Legacy
signatures will not transfer, and neither will most Legacy structure offsets derived from
them. Enhanced has to be re-derived from scratch.

Build timestamp on the analysed copy: `6A4F97F6` — Thu 09 Jul 2026.

---

## The disk binary is not worth disassembling

Loading `GTA5_Enhanced.exe` from disk into IDA 7.7 produces:

* **Garbage at the entry of `.text`.** `0x140001000` disassembles to `out dx, eax`,
  `movsb`, `lodsd`, `cld`/`std` — 16-bit DOS-era instructions no 64-bit compiler emits.
* **A navigator bar that is almost entirely "Unexplored".**
* **~10,500 functions** identified across 46.8 MB of code. That should be well into six
  figures.

IDA's own header parse does agree with Violet's runtime recon exactly — image base
`140000000`, section 1 virtual size `0x02479400` = 38,245,376 bytes — so the *headers* are
honest. It is the code that isn't.

**Therefore: analyse a memory dump, not the file.** By the time Violet is running, the
loader has mapped the image, applied relocations and resolved imports, and anything that
unpacks at runtime has already done so — the CPU has to execute real instructions
eventually. `mem/dump.cpp` writes the mapped image back out with section headers rewritten
to `PointerToRawData = VirtualAddress`, `SizeOfRawData = VirtualSize`, and the original
image base restored, so the result opens in IDA at `0x140000000` with every address still
matching the live process.

---

## The game's window

Captured live from inside the process:

| | |
|---|---|
| Window class | **`sgaWindow`** (GTA V Legacy used `grcWindow`) |
| Title | `Grand Theft Auto V` |
| Style | `0x96000000` = `WS_POPUP \| WS_VISIBLE \| WS_CLIPSIBLINGS \| WS_CLIPCHILDREN` |
| Ex-style | `0x00000000` — **not** `WS_EX_TOPMOST` |

`WS_POPUP` with no border means window rect and client rect are identical, so there is no
title-bar offset to compensate for when aligning an overlay — `ClientToScreen({0,0})` is
simply the window's top-left.

Violet does not hardcode the class name; it picks the largest visible unowned window
belonging to the process, and logs every candidate it considered. A game update can rename
the class without breaking anything.

**The overlay is not `WS_EX_TOPMOST`-blocked.** Since the game does not set that flag,
an overlay that does is in a strictly higher z-order band. But ordering *within* the
topmost band still follows activation, so the overlay must periodically re-assert
`SetWindowPos(HWND_TOPMOST, ...)` or it sinks behind the game once the game takes focus.
That is what `keep_on_top()` in `render/overlay.cpp` exists for.

---

---

## The native table: what we ruled out

Three automated hunts, all run against a live session via `probe.dll`. All three
came back negative, and the negatives are informative.

### 1. The classic structure is not present

Searched every writable, non-executable section of the module (5.1 M slots in `.data`
alone, 112 ms) for the historical RAGE layout — `next` at `+0x00`, seven handlers at
`+0x08`, a count of 1–7 at `+0x40`.

**Best 256-slot window held 29 valid blocks.** A real table would hold most of 256.

### 2. Native hashes are NOT stored in plaintext

Swept all 7.6 GB of readable memory for two hashes verified against the CitizenFX
native database:

| Native | Hash |
|---|---|
| `GET_PLAYER_PED` | `0x43A66C31C68491C0` |
| `SET_ENTITY_COORDS` | `0x06843DA7060A026B` |

**Two hits each — and both were the probe's own constants.** The bytes around them
decoded to `"GET_PLAY" "ER_PED" "SET_ENTI" "TY_COORD"`: our own `k_known` array and its
string literals, sitting in the DLL we had just injected.

The hashes are encrypted in memory. The table cannot be found by searching for them.

### 3. There is no linked list of code-pointer blocks

The one property a vtable cannot imitate: registration blocks form a chain, each
pointing at the next. Tested handler-array offsets `+0x08`, `+0x10`, `+0x18`, `+0x20`.

**Longest chain at any offset: 2 blocks. Zero chains of 8 or more.**

For contrast, the earlier layout probe found **21,128** blocks with runs of code pointers
starting at `+0x00` — those are ordinary C++ vtables, and they are everywhere. So the
scan is working; there simply is no chain to find.

### Strong candidate found: RVA `0x3ED4C20`

Searching for **runs of pointers into heap**, making no assumption about what they point
to, surfaced a run of **exactly 256** in `.data`:

| | |
|---|---|
| Table RVA | **`0x3ED4C20`** |
| IDA address | `0x143ED4C20` |
| Entries | exactly 256 |

Four entries sampled across the table (slots 0, 64, 128, 192) all share one layout:

```
+0x00   opaque 64-bit
+0x08   heap-range value, aligned in some entries and not others
+0x10   \
 ...     >  fixed array of 7 handler slots, zero-padded when unused
+0x40   /
+0x48   opaque 64-bit values
 ...
```

Handler counts in the four samples were **7, 3, 6 and 4** — a fixed seven-slot array,
partially filled, which is exactly the shape of a registration block. The handlers are
plain pointers into executable memory; everything else is obfuscated.

**What is still missing: the chain.** `+0x08` sits in the heap address range but is
frequently *unaligned* (`0x1CE87AA77E4`), so it is not a usable `next` pointer as-is —
it is obfuscated like the hashes. Every attempt to walk the table therefore terminates
after one block, which is why the automated scan reports ~10-30 natives instead of
several thousand.

### What that leaves

Hashes are encrypted, and the absence of *any* chain of blocks containing raw code
pointers strongly suggests **the handler pointers are encrypted too**. If a handler is
stored XOR'd, or as an RVA, or behind an indirection, then "does this value point at
executable memory?" can never fire — which is exactly what we observe.

This is consistent with what later GTA V builds are known to do, and it is why tools
targeting the game need updating on every patch.

**So the way in is `GetNativeHandler` itself.** That function takes a hash and returns a
handler, which means it necessarily contains the decryption. Find it and the encryption
stops mattering — we call it rather than reimplement it.

Finding it means disassembly, which means the memory dump, which is why the IDA analysis
matters. Legacy signatures will not help: Enhanced is a Clang build (see the PDB path
above) and every published pattern came from MSVC.

---

## Open questions

- [ ] Which mitigations are set? (`DllCharacteristics` — added to recon, not yet re-run.)
      **CFG** in particular constrains how we hook indirect calls. `.00cfg` is present,
      which suggests `/guard:cf` was used.
- [ ] Do the on-disk and in-memory `.text` bytes agree? Decides the IDA strategy.
- [ ] Does `SocialClubD3D12Renderer.dll` own the swapchain, or hook the game's?
