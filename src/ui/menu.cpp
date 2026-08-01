#include "ui/menu.hpp"

#include "core/log.hpp"
#include "core/process.hpp"
#include "input/gamepad.hpp"
#include "render/overlay.hpp"

#include <Windows.h>

#include "imgui.h"

#include <cstdio>
#include <optional>
#include <string>

namespace violet::ui
{
namespace
{
    // The palette. One place to change Violet's whole look.
    constexpr ImVec4 k_violet      { 0.659f, 0.333f, 0.969f, 1.00f };   // #A855F7
    constexpr ImVec4 k_violet_dim  { 0.545f, 0.361f, 0.965f, 1.00f };
    constexpr ImVec4 k_violet_deep { 0.427f, 0.157f, 0.851f, 1.00f };
    constexpr ImVec4 k_bg          { 0.055f, 0.043f, 0.086f, 0.94f };
    constexpr ImVec4 k_bg_light    { 0.110f, 0.086f, 0.169f, 1.00f };
    constexpr ImVec4 k_text        { 0.925f, 0.910f, 0.960f, 1.00f };
    constexpr ImVec4 k_text_dim    { 0.560f, 0.540f, 0.620f, 1.00f };

    ImFont* g_font_ui   = nullptr;   // Segoe UI          - body text
    ImFont* g_font_bold = nullptr;   // Segoe UI Semibold - headings
    ImFont* g_font_mono = nullptr;   // Cascadia Mono     - hex, addresses

    std::optional<violet::process::ModuleInfo> g_module;

    // Two-step guard on the unload button - see the footer in draw().
    bool g_unload_armed = false;

    // -----------------------------------------------------------------------
    // fonts
    // -----------------------------------------------------------------------

    void load_fonts()
    {
        ImGuiIO& io = ImGui::GetIO();

        // Resolved rather than hardcoded to C:\Windows - the system directory
        // is not guaranteed to be on C:, and asking costs one API call.
        char windows_dir[MAX_PATH]{};
        GetWindowsDirectoryA(windows_dir, MAX_PATH);
        const std::string fonts = std::string{ windows_dir } + "\\Fonts\\";

        const auto load = [&](const char* file, float size) -> ImFont*
        {
            const std::string path = fonts + file;
            if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                VIOLET_WARN("  font not found: {}", path);
                return nullptr;
            }
            return io.Fonts->AddFontFromFileTTF(path.c_str(), size);
        };

        g_font_ui   = load("segoeui.ttf",      17.0f);
        g_font_bold = load("seguisb.ttf",      17.0f);
        g_font_mono = load("CascadiaMono.ttf", 15.0f);

        // Always leave with something usable. AddFontDefaultVector is new in
        // 1.92 - unlike the old bitmap default it stays sharp when scaled, so
        // it is a genuinely acceptable fallback rather than a punishment.
        if (g_font_ui == nullptr)
        {
            VIOLET_WARN("  falling back to ImGui's built-in vector font");
            g_font_ui = io.Fonts->AddFontDefaultVector();
        }
        if (g_font_bold == nullptr) g_font_bold = g_font_ui;
        if (g_font_mono == nullptr) g_font_mono = g_font_ui;

        io.FontDefault = g_font_ui;
        VIOLET_INFO("  fonts loaded");
    }

    // -----------------------------------------------------------------------
    // small helpers
    // -----------------------------------------------------------------------

    void heading(const char* label)
    {
        ImGui::Dummy({ 0.0f, 6.0f });

        // PushFont(font, 0.0f) means "this font, keep the current size".
        ImGui::PushFont(g_font_bold, 0.0f);
        ImGui::PushStyleColor(ImGuiCol_Text, k_violet);
        ImGui::TextUnformatted(label);
        ImGui::PopStyleColor();
        ImGui::PopFont();

        ImGui::Separator();
        ImGui::Dummy({ 0.0f, 3.0f });
    }

    void key_value(const char* key, const char* value, bool mono = false)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
        ImGui::TextUnformatted(key);
        ImGui::PopStyleColor();

        ImGui::SameLine(170.0f);

        if (mono) ImGui::PushFont(g_font_mono, 0.0f);
        ImGui::TextUnformatted(value);
        if (mono) ImGui::PopFont();
    }

    void placeholder(const char* text)
    {
        ImGui::Dummy({ 0.0f, 4.0f });
        ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
        ImGui::TextWrapped("%s", text);
        ImGui::PopStyleColor();
    }

    // -----------------------------------------------------------------------
    // watermark
    // -----------------------------------------------------------------------

    // A small always-on marker so you can tell Violet is alive and tracking the
    // window correctly without opening the menu. Also the fastest way to spot
    // the overlay drifting out of alignment.
    void draw_watermark()
    {
        const ImGuiViewport* vp = ImGui::GetMainViewport();

        ImGui::SetNextWindowPos({ vp->WorkPos.x + 14.0f, vp->WorkPos.y + 14.0f });
        ImGui::SetNextWindowBgAlpha(0.35f);

        constexpr auto flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                               ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                               ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoInputs;

        if (ImGui::Begin("##violet_watermark", nullptr, flags))
        {
            ImGui::PushFont(g_font_bold, 0.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, k_violet);
            ImGui::TextUnformatted("VIOLET");
            ImGui::PopStyleColor();
            ImGui::PopFont();

            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
            ImGui::Text("%.0f fps", ImGui::GetIO().Framerate);
            ImGui::PopStyleColor();
        }
        ImGui::End();
    }

    // -----------------------------------------------------------------------
    // tabs
    // -----------------------------------------------------------------------

    void tab_status(const ImGuiViewport* vp)
    {
        char buf[128];

        heading("Overlay");

        std::snprintf(buf, sizeof(buf), "%.0f fps   %.2f ms",
                      ImGui::GetIO().Framerate, 1000.0f / ImGui::GetIO().Framerate);
        key_value("render", buf, true);

        std::snprintf(buf, sizeof(buf), "%.0f x %.0f", vp->WorkSize.x, vp->WorkSize.y);
        key_value("viewport", buf, true);

        key_value("compositing", "DirectComposition");
        key_value("swapchain", "B8G8R8A8 premultiplied", true);

        heading("Input");

        const auto& gp = violet::input::poll();
        key_value("controller", gp.connected ? "connected" : "not detected");
        key_value("toggle", "END  /  PAGE UP  /  D-pad LEFT + RT");
        key_value("move", "D-pad  or  left stick");
        key_value("select", "A  select,   B  back");
        key_value("scroll", "right stick   (LB / RB to slow / speed)");

        if (g_module)
        {
            heading("Host process");

            std::snprintf(buf, sizeof(buf), "0x%llX",
                          static_cast<unsigned long long>(g_module->base));
            key_value("module base", buf, true);

            std::snprintf(buf, sizeof(buf), "0x%llX",
                          static_cast<unsigned long long>(g_module->preferred_base));
            key_value("IDA base", buf, true);

            const auto slide = g_module->slide();
            std::snprintf(buf, sizeof(buf), "%c0x%llX", slide < 0 ? '-' : '+',
                          static_cast<unsigned long long>(slide < 0 ? -slide : slide));
            key_value("slide", buf, true);

            std::snprintf(buf, sizeof(buf), "%.1f MB in %zu section(s)",
                          static_cast<double>(g_module->total_executable_bytes()) / (1024.0 * 1024.0),
                          g_module->executable_sections().size());
            key_value("scannable code", buf, true);
        }
    }
}

// ---------------------------------------------------------------------------
// public
// ---------------------------------------------------------------------------

void apply_theme()
{
    load_fonts();

    ImGuiStyle& s = ImGui::GetStyle();

    s.WindowRounding    = 10.0f;
    s.ChildRounding     = 6.0f;
    s.FrameRounding     = 6.0f;
    s.PopupRounding     = 6.0f;
    s.ScrollbarRounding = 6.0f;
    s.GrabRounding      = 6.0f;
    s.TabRounding       = 6.0f;

    s.WindowBorderSize  = 1.0f;
    s.FrameBorderSize   = 0.0f;
    s.WindowPadding     = { 18.0f, 16.0f };
    s.FramePadding      = { 10.0f, 6.0f };
    s.ItemSpacing       = { 10.0f, 8.0f };
    s.ItemInnerSpacing  = {  8.0f, 6.0f };
    s.ScrollbarSize     = 12.0f;
    s.TabBarBorderSize  = 0.0f;

    ImVec4* c = s.Colors;

    c[ImGuiCol_Text]                 = k_text;
    c[ImGuiCol_TextDisabled]         = k_text_dim;
    c[ImGuiCol_WindowBg]             = k_bg;
    c[ImGuiCol_ChildBg]              = { 0.0f, 0.0f, 0.0f, 0.0f };
    c[ImGuiCol_PopupBg]              = { 0.071f, 0.055f, 0.110f, 0.98f };
    c[ImGuiCol_Border]               = { k_violet.x, k_violet.y, k_violet.z, 0.24f };
    c[ImGuiCol_BorderShadow]         = { 0.0f, 0.0f, 0.0f, 0.0f };

    c[ImGuiCol_FrameBg]              = k_bg_light;
    c[ImGuiCol_FrameBgHovered]       = { k_violet.x, k_violet.y, k_violet.z, 0.30f };
    c[ImGuiCol_FrameBgActive]        = { k_violet.x, k_violet.y, k_violet.z, 0.45f };

    // Deliberately restrained: a saturated violet title bar reads as loud, and
    // this window sits on top of a game the user is trying to look at.
    c[ImGuiCol_TitleBg]              = { 0.086f, 0.063f, 0.145f, 1.0f };
    c[ImGuiCol_TitleBgActive]        = { 0.153f, 0.098f, 0.267f, 1.0f };
    c[ImGuiCol_TitleBgCollapsed]     = { 0.055f, 0.043f, 0.086f, 0.75f };

    c[ImGuiCol_Header]               = { k_violet.x, k_violet.y, k_violet.z, 0.30f };
    c[ImGuiCol_HeaderHovered]        = { k_violet.x, k_violet.y, k_violet.z, 0.50f };
    c[ImGuiCol_HeaderActive]         = k_violet_dim;

    c[ImGuiCol_Button]               = { k_violet.x, k_violet.y, k_violet.z, 0.28f };
    c[ImGuiCol_ButtonHovered]        = { k_violet.x, k_violet.y, k_violet.z, 0.52f };
    c[ImGuiCol_ButtonActive]         = k_violet_dim;

    c[ImGuiCol_CheckMark]            = k_violet;
    c[ImGuiCol_SliderGrab]           = k_violet_dim;
    c[ImGuiCol_SliderGrabActive]     = k_violet;

    c[ImGuiCol_Separator]            = { k_violet.x, k_violet.y, k_violet.z, 0.22f };
    c[ImGuiCol_SeparatorHovered]     = { k_violet.x, k_violet.y, k_violet.z, 0.55f };
    c[ImGuiCol_SeparatorActive]      = k_violet;

    c[ImGuiCol_Tab]                  = { 0.094f, 0.071f, 0.153f, 1.0f };
    c[ImGuiCol_TabHovered]           = { k_violet.x, k_violet.y, k_violet.z, 0.45f };
    c[ImGuiCol_TabSelected]          = { 0.278f, 0.145f, 0.522f, 1.0f };
    c[ImGuiCol_TabDimmed]            = { 0.078f, 0.059f, 0.125f, 1.0f };
    c[ImGuiCol_TabDimmedSelected]    = { 0.176f, 0.098f, 0.341f, 1.0f };

    c[ImGuiCol_ScrollbarBg]          = { 0.0f, 0.0f, 0.0f, 0.20f };
    c[ImGuiCol_ScrollbarGrab]        = { k_violet.x, k_violet.y, k_violet.z, 0.32f };
    c[ImGuiCol_ScrollbarGrabHovered] = { k_violet.x, k_violet.y, k_violet.z, 0.55f };
    c[ImGuiCol_ScrollbarGrabActive]  = k_violet;

    c[ImGuiCol_NavCursor]            = k_violet;
}

void draw()
{
    // Cached: parsing PE headers every frame would be pointless work, and the
    // answer cannot change while the process is alive.
    if (!g_module)
        g_module = violet::process::inspect(nullptr);

    draw_watermark();

    if (!violet::render::menu_visible())
    {
        g_unload_armed = false;   // closing the menu cancels a pending unload
        return;
    }

    const ImGuiViewport* vp = ImGui::GetMainViewport();

    ImGui::SetNextWindowPos({ vp->WorkPos.x + vp->WorkSize.x * 0.5f,
                              vp->WorkPos.y + vp->WorkSize.y * 0.5f },
                            ImGuiCond_FirstUseEver, { 0.5f, 0.5f });
    ImGui::SetNextWindowSize({ 520.0f, 560.0f }, ImGuiCond_FirstUseEver);

    if (!ImGui::Begin("Violet", nullptr, ImGuiWindowFlags_NoCollapse))
    {
        ImGui::End();
        return;
    }

    // ---- brand ----
    const float base = ImGui::GetStyle().FontSizeBase;

    ImGui::PushFont(g_font_bold, base * 1.55f);
    ImGui::PushStyleColor(ImGuiCol_Text, k_violet);
    ImGui::TextUnformatted("VIOLET");
    ImGui::PopStyleColor();
    ImGui::PopFont();

    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
    ImGui::TextUnformatted("v0.1.0");
    ImGui::PopStyleColor();

    ImGui::Dummy({ 0.0f, 4.0f });

    if (ImGui::BeginTabBar("##violet_tabs"))
    {
        if (ImGui::BeginTabItem("Status"))
        {
            tab_status(vp);
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Self"))
        {
            placeholder(
                "Empty until stage 5.\n\n"
                "God mode, health, armour, wanted level - all of it works by calling the "
                "game's own scripting functions, its \"natives\". We cannot call one yet, "
                "because we have not found the table that maps a native's ID to the "
                "address of the code implementing it.\n\n"
                "Finding that table is the reverse-engineering chapter.");
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("World"))
        {
            placeholder("Teleports, time and weather. Also stage 5.");
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("AI"))
        {
            placeholder(
                "The offline lobby. Stage 7.\n\n"
                "Spawned peds running a behaviour state machine - wander, drive, engage, "
                "flee, regroup - with nametags and blips, so single player feels populated "
                "the way a GTA Online session does.");
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Demo"))
        {
            placeholder(
                "ImGui ships a demo window showing every widget it has, with the source "
                "for each. It is the fastest way to see what is available while building "
                "the real menu.");

            ImGui::Dummy({ 0.0f, 8.0f });
            static bool show_demo = false;
            ImGui::Checkbox("Show the ImGui demo window", &show_demo);
            if (show_demo)
                ImGui::ShowDemoWindow(&show_demo);

            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    // ---- footer, pinned to the bottom of the window ----
    const float footer = ImGui::GetTextLineHeightWithSpacing() + ImGui::GetStyle().ItemSpacing.y;
    const float remaining = ImGui::GetContentRegionAvail().y - footer;
    if (remaining > 0.0f)
        ImGui::Dummy({ 0.0f, remaining });

    ImGui::Separator();
    ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
    ImGui::TextUnformatted("END / PAGE UP / D-pad LEFT + RT   close");
    ImGui::PopStyleColor();

    // Unload, right-aligned and deliberately two-step. On a controller the A
    // button activates whatever the nav cursor happens to be sitting on, and
    // silently removing Violet from the process on a stray press would be a
    // genuinely irritating way to lose your session.
    {
        const char* label = g_unload_armed ? "Confirm unload" : "Unload Violet";
        const float width = ImGui::CalcTextSize(label).x + ImGui::GetStyle().FramePadding.x * 2.0f;

        ImGui::SameLine();
        ImGui::SetCursorPosX(ImGui::GetWindowWidth() - width - ImGui::GetStyle().WindowPadding.x);

        const ImVec4 idle  = g_unload_armed ? ImVec4{ 0.62f, 0.16f, 0.22f, 0.90f }
                                            : ImVec4{ k_violet.x, k_violet.y, k_violet.z, 0.22f };
        const ImVec4 hover = g_unload_armed ? ImVec4{ 0.78f, 0.20f, 0.27f, 1.00f }
                                            : ImVec4{ k_violet.x, k_violet.y, k_violet.z, 0.45f };

        ImGui::PushStyleColor(ImGuiCol_Button,        idle);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  hover);

        if (ImGui::Button(label))
        {
            if (g_unload_armed)
                violet::render::request_unload();
            else
                g_unload_armed = true;
        }

        ImGui::PopStyleColor(3);

        if (g_unload_armed && ImGui::IsItemHovered())
            ImGui::SetTooltip("Violet will detach from the game.\n"
                              "You can inject a fresh build straight away -\n"
                              "no need to restart GTA.");
    }

    ImGui::End();
}
}
