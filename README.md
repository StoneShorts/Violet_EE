# Violet

A single-player mod menu for **GTA V Enhanced**, written from scratch in C++.

No ScriptHookV, no borrowed injector, no copied offset tables. Every piece — the DLL
injector, the PE parser, the DirectX 12 overlay, the pattern scanner — is built here and
explained in the comments. It's a working tool *and* a readable walkthrough of how PC game
modding actually works underneath the frameworks that usually hide it.

> ### Story Mode only
>
> Violet targets single-player. It does nothing for GTA Online, it isn't built to, and
> taking tools like this online gets you banned and ruins other people's games. Rockstar
> provides a BattlEye toggle specifically so single-player modding is possible — that's
> the box this lives in.

---

## Status

Working today: Violet injects into the game, parses its PE layout, renders a themed,
controller-navigable ImGui overlay, and drives a working set of trainer features.

| Stage | | |
|---|---|:--|
| 1 | Toolchain, DLL injection, logging | ✅ |
| 2 | PE parsing & process recon | ✅ |
| 3 | DirectX 12 overlay + Dear ImGui | ✅ |
| 4 | Keyboard & controller input | ✅ |
| 5 | Signature scanner, memory dumper, live probe | ✅ |
| 5b | From-scratch native table | 🔬 research, see below |
| 6 | Trainer features | ✅ god mode · health · armour · wanted level · weapons · teleport · time · weather |
| 7 | AI NPC "offline lobby" | 🚧 next |

## The native layer

The Self / Weapons / World tabs need **Script Hook V (Enhanced)** — the build matching
your game version. Drop `ScriptHookV.dll` and `dinput8.dll` next to `GTA5_Enhanced.exe`.

Violet binds to it **at runtime via `GetProcAddress`**; nothing is vendored here, and a
static import that failed to resolve would stop the whole DLL loading. Without it you
still get the overlay, the scanner, the dumper and every analysis tool — just no cheats,
with the menu saying so plainly rather than sitting there dead.

**Why one component is borrowed.** Calling a native means turning a 64-bit hash into an
engine function address. On Enhanced the hashes are *encrypted in memory* — a sweep of all
7.6 GB found only Violet's own probe constants — and the registration blocks' chain
pointer is obfuscated too, so the table cannot be walked. Enhanced is also a Clang build
(the leftover PDB path says `game_win64_gdk_master_llvm.pdb`), so no published offsets
from GTA V Legacy transfer.

That research continues and is written up in
[`docs/02-recon-findings.md`](docs/02-recon-findings.md). It just shouldn't be the thing
standing between this project and a menu that works.
| 7 | AI NPC "offline lobby" | |

The end goal for stage 7: spawned NPCs running a behaviour state machine — wander, drive,
engage, flee, regroup — with nametags and blips, so Story Mode feels as populated as a
GTA Online session, entirely offline.

---

## How it works

### It doesn't hook the game's renderer

The usual way to draw over a game is to hook its swapchain's `Present` and render inside
the game's frame. Violet deliberately doesn't.

On a typical machine that swapchain already has several hooks in it — NVIDIA's overlay,
Ansel, Discord, and Rockstar's own Social Club renderer. Those coexist fine with each
other. The problem is that adding one more means that when something misbehaves, you have
four other people's hooks to rule out before you can trust your own code.

So Violet creates **its own window** instead: transparent, click-through, always-on-top,
with its own D3D12 device, kept glued over the game's client area. The game's rendering is
never touched. It doesn't know Violet exists.

Transparency comes from **DirectComposition** rather than the old `WS_EX_LAYERED` colour-key
trick, which has no per-pixel alpha and turns every black pixel in your UI into a hole.
The window is created with `WS_EX_NOREDIRECTIONBITMAP`, the swapchain via
`CreateSwapChainForComposition` with `DXGI_ALPHA_MODE_PREMULTIPLIED`, and the two are bound
through a composition visual. Clearing to transparent black then lines up exactly with
ImGui's blend state, so alpha works for free.

**Trade-off:** this needs borderless or windowed mode. Exclusive fullscreen hands the
display straight to the game and bypasses the compositor, so nothing can draw on top of
it. It also won't appear in ShadowPlay clips or in-game screenshots, since those capture
the game's swapchain and Violet isn't in it.

### Everything is found, not hardcoded

Absolute addresses rot. They break when Windows relocates the image, and they break far
worse when the game is patched and every offset shifts. Violet reads the PE headers at
runtime to find its own scan ranges, and the notes in `docs/` record findings as **RVAs**
rather than addresses.

Two things that binary turned out to teach us, both written up in
[`docs/02-recon-findings.md`](docs/02-recon-findings.md):

- `GTA5_Enhanced.exe` has **two separate `.text` sections**, 36.5 MB and 10.4 MB. Code that
  searches "the section named `.text`" finds the first and silently misses 22% of the
  binary, with no error to explain why a pattern that genuinely exists won't match.
- Sections appear **after `.reloc`**, section names are duplicated, and `.idata` is its own
  writable section. All three mean a tool rewrote the binary after the linker finished —
  which changes how much you can trust a static disassembly of the file on disk.

---

## Quick start

Requires **Visual Studio 2022** (Desktop C++ workload), **CMake 3.20+**, and the Windows
10/11 SDK. x64 only.

Launch GTA V Enhanced into Story Mode, wait until you're actually standing in the world,
then run:

```bash
violet.bat
```

That fetches Dear ImGui if it's missing, configures CMake on first run, builds, checks the
game is running and not already injected, and injects. It reports precisely which step
failed if one does.

Everything below is the same thing done by hand.

## Building

Fetch Dear ImGui, which is not vendored:

```bash
git clone --depth 1 https://github.com/ocornut/imgui.git third_party/imgui
```

Configure and build:

```bash
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
```

```bash
cmake --build build --config Release
```

Binaries land in `bin/`. To use the IDE instead, open `build/Violet.sln`.

## Running

Set the game to **Borderless** (Settings → Graphics → Screen Type), launch into Story
Mode, wait until you're actually in the world, then:

```bash
bin\inject.exe GTA5_Enhanced.exe bin\Violet.dll
```

| | |
|---|---|
| <kbd>End</kbd> or <kbd>Page&nbsp;Up</kbd> | toggle the menu |
| D-pad&nbsp;left + right&nbsp;trigger | toggle the menu (hold briefly) |
| D-pad / left stick, **A**, **B** | navigate, select, back |

Violet unloads itself when the game closes, and the menu has an **Unload Violet** button
that detaches it cleanly — you can inject a fresh build straight afterwards without
restarting the game.

Diagnostics go to `%LOCALAPPDATA%\Violet\Violet.log`, to a debug console, and to any
attached debugger.

> The injector deliberately loads a uniquely-named **copy** of the DLL from a staging
> folder. Windows holds an exclusive lock on a loaded DLL, so injecting the build output
> directly would make your next build fail with `LNK1104` until you unloaded.

**Back up your saves first** — `Documents\Rockstar Games\GTA V Enhanced\Profiles\`. A
misbehaving mod can corrupt a save, and no playthrough deserves that.

### If the overlay is invisible

Read `bin/Violet.log`. It reports the game's window rectangle, style flags, and whether the
window covers the whole monitor — enough to tell windowed from borderless from exclusive
fullscreen. Exclusive fullscreen is the usual answer.

---

## Layout

```
src/
  main.cpp            DllMain and startup
  core/log.*          file + console + debugger logging
  core/process.*      PE header parsing, section map, module scan
  input/gamepad.*     XInput, loaded dynamically
  render/overlay.*    the window, D3D12, DirectComposition, the frame loop
  render/srv_heap.hpp descriptor allocator with a free list
  ui/menu.*           theme and interface

tools/
  injector/           inject.exe
  testhost/           a stand-in window, so you can test without launching the game

docs/                 roadmap and reverse-engineering notes
```

`testhost.exe` is worth knowing about if you're building on this: it's a plain 1280x720
window that Violet will attach to exactly like the game. Iterating against it takes
seconds instead of a full game launch, and a crash costs nothing.

## Built with

[Dear ImGui](https://github.com/ocornut/imgui) by Omar Cornut. Everything else is in this
repository.
