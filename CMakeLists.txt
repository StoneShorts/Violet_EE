cmake_minimum_required(VERSION 3.20)

project(Violet
    VERSION     0.1.0
    DESCRIPTION "Violet - a single-player GTA V Enhanced mod menu, built from scratch"
    LANGUAGES   CXX)

# ---------------------------------------------------------------------------
# Architecture guard.
#
# GTA5_Enhanced.exe is a 64-bit process. A 32-bit DLL physically cannot be
# loaded into a 64-bit process - the loader will reject it outright. This check
# turns that into a clear error at configure time instead of a confusing
# "injection failed" three steps later.
# ---------------------------------------------------------------------------
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Violet must be built as x64. Re-configure with:  -A x64")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Output layout.
#
# Visual Studio is a "multi-config" generator: it normally buries binaries in
# build/Debug/ and build/Release/. We override every config to dump everything
# into one flat <project>/bin/ folder so the DLL is always at the same path and
# your inject command never changes.
# ---------------------------------------------------------------------------
foreach(cfg "" _DEBUG _RELEASE _RELWITHDEBINFO _MINSIZEREL)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY${cfg} "${CMAKE_SOURCE_DIR}/bin")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY${cfg} "${CMAKE_SOURCE_DIR}/bin")
endforeach()

# Compile flags shared by every target we build.
add_library(violet_common_flags INTERFACE)
target_compile_definitions(violet_common_flags INTERFACE
    WIN32_LEAN_AND_MEAN   # trims windows.h - much faster builds, fewer name clashes
    NOMINMAX              # stops windows.h defining min/max macros that break std::min
    UNICODE _UNICODE      # Win32 API defaults to the wide-char (W) functions
)
target_compile_options(violet_common_flags INTERFACE
    /W4        # high warning level - warnings here are usually real bugs
    /permissive-
    /utf-8
)

# ---------------------------------------------------------------------------
# Dear ImGui (third_party/imgui, cloned from github.com/ocornut/imgui)
#
# Built as its own static library rather than compiled into Violet directly,
# for one practical reason: it lets us hold OUR code to /W4 while not holding
# somebody else's code to a warning level they never agreed to.
# ---------------------------------------------------------------------------
set(IMGUI_DIR "${CMAKE_SOURCE_DIR}/third_party/imgui")

if(NOT EXISTS "${IMGUI_DIR}/imgui.cpp")
    message(FATAL_ERROR
        "Dear ImGui is missing. Fetch it with:\n"
        "  git clone --depth 1 https://github.com/ocornut/imgui.git third_party/imgui")
endif()

add_library(imgui STATIC
    "${IMGUI_DIR}/imgui.cpp"
    "${IMGUI_DIR}/imgui_draw.cpp"
    "${IMGUI_DIR}/imgui_tables.cpp"
    "${IMGUI_DIR}/imgui_widgets.cpp"
    "${IMGUI_DIR}/imgui_demo.cpp"                      # the widget gallery - useful to learn from
    "${IMGUI_DIR}/backends/imgui_impl_win32.cpp"
    "${IMGUI_DIR}/backends/imgui_impl_dx12.cpp"
)
target_include_directories(imgui PUBLIC "${IMGUI_DIR}" "${IMGUI_DIR}/backends")
target_compile_definitions(imgui PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX

    # We drive gamepad input ourselves from src/input/gamepad.cpp. ImGui's
    # backend only polls controller slot 0 and only notices a pad appearing on
    # WM_DEVICECHANGE, which our tool window may never receive. See the comment
    # on feed_imgui() in input/gamepad.hpp.
    IMGUI_IMPL_WIN32_DISABLE_GAMEPAD
)
target_compile_options(imgui PRIVATE /W1 /utf-8)
target_link_libraries(imgui PUBLIC d3d12 dxgi dxguid)

# ---------------------------------------------------------------------------
# Violet.dll  --  the mod menu itself. This is what gets injected.
# ---------------------------------------------------------------------------
add_library(Violet SHARED
    src/main.cpp
    src/core/log.cpp
    src/core/process.cpp
    src/input/gamepad.cpp
    src/game/features.cpp
    src/game/lobby.cpp
    src/game/native_table.cpp
    src/game/scripthook.cpp
    src/mem/dump.cpp
    src/mem/pattern.cpp
    src/mem/regions.cpp
    src/render/overlay.cpp
    src/ui/menu.cpp
)
target_include_directories(Violet PRIVATE src)
target_link_libraries(Violet PRIVATE
    violet_common_flags
    imgui
    d3d12       # the graphics API
    dxgi        # swapchain / adapter enumeration
    dxguid      # the IID_* GUID constants IID_PPV_ARGS expands to
    dcomp       # DirectComposition - what makes the window transparent
)

# ---------------------------------------------------------------------------
# inject.exe  --  our own DLL injector. We are not using anyone else's.
# ---------------------------------------------------------------------------
add_executable(inject tools/injector/main.cpp)
target_link_libraries(inject PRIVATE violet_common_flags)

# ---------------------------------------------------------------------------
# testhost.exe  --  a safe, unsandboxed process to practise injecting into,
# so our first attempt isn't also our first time launching the game.
#
# WIN32_EXECUTABLE means "GUI subsystem": entry point is wWinMain and the
# process starts with no console of its own - which is what lets Violet's
# AllocConsole visibly succeed.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# probe.dll  --  analysis only, no UI.
#
# Safe to inject into a session that already has Violet running: it has no
# window, no hotkeys, and writes to its own log, then unloads itself. Lets us
# iterate on "what are we looking for" against a live game without restarting
# anything.
# ---------------------------------------------------------------------------
add_library(probe SHARED
    tools/probe/main.cpp
    src/core/log.cpp
    src/core/process.cpp
    src/mem/regions.cpp
    src/game/invoker.cpp
    src/game/native_table.cpp
)
target_include_directories(probe PRIVATE src)
target_link_libraries(probe PRIVATE violet_common_flags)

add_executable(testhost tools/testhost/main.cpp)
target_link_libraries(testhost PRIVATE violet_common_flags)
set_target_properties(testhost PROPERTIES WIN32_EXECUTABLE TRUE)

message(STATUS "Violet ${PROJECT_VERSION} -> ${CMAKE_SOURCE_DIR}/bin")
