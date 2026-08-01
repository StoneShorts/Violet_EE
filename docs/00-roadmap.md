# Violet — roadmap

A single-player mod menu for **GTA V Enhanced**, written from scratch.

| | |
|---|---|
| Target | `GTA5_Enhanced.exe` — `1.0.1158.13` |
| Install | `C:\Program Files\Rockstar Games\Grand Theft Auto V Enhanced` |
| Graphics API | **DX12** (confirmed: `D3D12-REDIST\`, `amd_fidelityfx_dx12.dll`, no D3D11 shims) |
| Toolchain | MSVC 14.44 (VS2022 Community) · Windows SDK 10.0.26100 · CMake 3.31 |
| RE tools | IDA Pro 7.7 · Ghidra · x64dbg |
| Scope | **Single player only.** BattlEye disabled via Rockstar launcher settings. |

---

## Ground rules

**Single player only.** Everything here targets Story Mode with BattlEye off. Taking any
of this online is both an instant ban and a genuinely crappy thing to do to other players.
It's also technically pointless — the anti-cheat surface is a completely different problem.

**Back up your saves before the first injection.**
`%USERPROFILE%\Documents\Rockstar Games\GTA V Enhanced\Profiles\`
Copy that folder somewhere safe. A misbehaving script can corrupt a save, and you do not
want your first crash to cost you a 60-hour playthrough.

---

## The stages

Note the ordering: everything through stage 4 is pure Windows/DirectX engineering with
zero game knowledge required. That's deliberate — you get Violet visibly on screen and
controller-navigable *before* the hard reverse-engineering chapter, so when you hit
stage 5 you already have a working UI to print your findings onto.

### Stage 1 — Toolchain & first injection ← **we are here**
Build a DLL, build our own injector, get our code running inside another process.

* `DllMain`, the loader lock, and why you never do real work in it
* `CreateToolhelp32Snapshot` → `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`
* Module base addresses and ASLR — why hardcoded offsets rot
* **Win:** `Violet.log` written from inside a live process

### Stage 2 — Into GTA
Same technique, real target. Deal with whatever Enhanced does that Notepad doesn't.

* Timing: inject too early and the game hasn't finished setting itself up
* Anti-debug / anti-tamper reconnaissance
* Clean unload without crashing the host
* **Win:** module base of `GTA5_Enhanced.exe` logged from inside the game

### Stage 3 — DX12 hook + ImGui
The big visible one. No game reverse engineering required — this is all documented API.

* How a swapchain presents a frame, and where we splice in
* Finding `IDXGISwapChain3::Present` via a dummy device (not by scanning the game)
* VTable hooking vs. trampoline hooking
* DX12 specifics that DX11 tutorials won't prepare you for: command queues, multiple back buffers, descriptor heaps, per-frame resources
* ImGui's DX12 backend, wired to the game's real device
* **Win:** a violet-themed window rendering over Los Santos

### Stage 4 — Input
* `WndProc` hooking to intercept keyboard/mouse before the game sees it
* Input blocking so the camera doesn't spin while you navigate a menu
* **XInput** for controller: sticks, deadzones, repeat-rate, chorded open/close
* **Win:** navigate Violet entirely from a pad

### Stage 5 — The reverse-engineering chapter
This is the part you actually came for.

* IDA workflow on a 56 MB binary; what Arxan-style protection does to it
* Writing an IDA-style signature scanner with wildcards
* RIP-relative addressing — how to turn `lea rcx, [rip+0x1234]` into a real pointer
* Finding the **native registration table** (GTA's ~6000 scripting functions)
* Building a native invoker: `NativeContext`, argument marshalling, return values
* Finding the **script thread** so our natives run on a thread that won't crash
* **Win:** offsets you found yourself, in a scanner that survives game updates

### Stage 6 — Violet's feature set
Self · Vehicle · Weapons · World · Teleports. The menu framework, properly built.

### Stage 7 — The AI NPC system
The end goal: an offline lobby that feels like GTA Online.

* Ped spawning, online-style models and outfits
* A per-bot behaviour state machine (wander / drive / engage / flee / regroup)
* Combat tasking so they actually fight each other and you
* Nametags and blips
* Session concept: bot count, spawn radius, respawn, kill feed
