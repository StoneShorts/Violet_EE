#include "ui/menu.hpp"

#include "core/log.hpp"
#include "core/process.hpp"
#include "input/gamepad.hpp"
#include "mem/dump.hpp"
#include "mem/pattern.hpp"
#include "render/overlay.hpp"

#include <Windows.h>

#include "imgui.h"

#include <cstdio>
#include <optional>
#include <string>
#include <vector>

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
    bool   g_unload_armed  = false;
    double g_unload_arm_at = 0.0;

    // ---- signature scanner tab state ----
    char        g_sig_input[512] = "48 89 5C 24 ? 57 48 83 EC";
    std::vector<std::uintptr_t> g_sig_hits;
    std::string g_sig_status  = "Enter an IDA-style signature and press Scan.";
    bool        g_sig_ok      = true;
    double      g_sig_ms      = 0.0;
    std::size_t g_sig_bytes   = 0;
    std::size_t g_sig_fixed   = 0;

    std::optional<violet::mem::SelfTest>    g_selftest;
    std::optional<violet::mem::DiskCompare> g_compare;
    std::optional<violet::mem::DumpResult>  g_dump;

    // ---- string / xref search state ----
    char        g_text_input[128] = "Rockstar";
    std::vector<std::uintptr_t>    g_text_hits;
    std::vector<violet::mem::Xref> g_xrefs;
    std::uintptr_t g_xref_target = 0;
    std::string    g_text_status = "Search for text that exists in the game's data.";
    double         g_text_ms     = 0.0;
    double         g_xref_ms     = 0.0;

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

    void run_signature_scan()
    {
        g_sig_hits.clear();

        const auto pattern = violet::mem::Pattern::parse(g_sig_input);
        if (!pattern)
        {
            g_sig_ok     = false;
            g_sig_status = "Malformed signature. Use hex byte pairs and ? for wildcards.";
            return;
        }

        g_sig_fixed = pattern->fixed_count();
        g_sig_hits  = violet::mem::scan_all(*pattern, 64);
        g_sig_ms    = violet::mem::last_scan_ms();
        g_sig_bytes = violet::mem::last_scan_bytes();
        g_sig_ok    = true;

        if (g_sig_hits.empty())
            g_sig_status = "No match. Try wildcarding more bytes.";
        else if (g_sig_hits.size() == 1)
            g_sig_status = "Unique match - this is what you want.";
        else
            g_sig_status = "Matched in several places; add more fixed bytes to disambiguate.";

        VIOLET_INFO("scan '{}' -> {} match(es) in {:.1f} ms",
                    pattern->text(), g_sig_hits.size(), g_sig_ms);
    }

    void draw_find_text()
    {
        heading("Find text  ->  find the code that uses it");

        ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
        ImGui::TextWrapped(
            "A signature re-finds something you already located. This is how you find "
            "it the FIRST time. Nothing in the binary is labelled - except strings. "
            "Locate one, then find the instruction that points at it, and whatever "
            "function contains that instruction is the one that uses it.");
        ImGui::PopStyleColor();

        ImGui::Dummy({ 0.0f, 4.0f });

        ImGui::PushFont(g_font_mono, 0.0f);
        ImGui::SetNextItemWidth(-1.0f);
        const bool submitted = ImGui::InputText("##findtext", g_text_input, sizeof(g_text_input),
                                                ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopFont();

        if (ImGui::Button("Search text") || submitted)
        {
            g_text_hits.clear();
            g_xrefs.clear();
            g_xref_target = 0;

            g_text_hits = violet::mem::find_string(g_text_input, 64);
            g_text_ms   = violet::mem::last_scan_ms();

            g_text_status = g_text_hits.empty()
                ? "Not found in any data section. Try a different string - case matters."
                : "Found. Press 'refs' on a row to find the code that points at it.";

            VIOLET_INFO("find_string '{}' -> {} hit(s) in {:.1f} ms",
                        g_text_input, g_text_hits.size(), g_text_ms);
        }

        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
        ImGui::TextWrapped("%s", g_text_status.c_str());
        ImGui::PopStyleColor();

        if (g_text_hits.empty())
            return;

        char buf[128];
        std::snprintf(buf, sizeof(buf), "%zu occurrence(s) in %.1f ms",
                      g_text_hits.size(), g_text_ms);
        key_value("data hits", buf, true);

        if (ImGui::BeginTable("##strhits", 3,
                              ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                              ImGuiTableFlags_ScrollY, { 0.0f, 130.0f }))
        {
            ImGui::TableSetupColumn("address");
            ImGui::TableSetupColumn("IDA");
            ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();

            int row = 0;
            for (const auto address : g_text_hits)
            {
                const violet::mem::ScanResult r{ address };
                ImGui::TableNextRow();
                ImGui::PushID(row++);

                ImGui::TableNextColumn();
                ImGui::PushFont(g_font_mono, 0.0f);
                ImGui::Text("0x%llX", (unsigned long long)address);
                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", (unsigned long long)r.ida());
                ImGui::PopFont();

                ImGui::TableNextColumn();
                if (ImGui::SmallButton("refs"))
                {
                    g_xref_target = address;
                    g_xrefs       = violet::mem::find_references(address, 64);
                    g_xref_ms     = violet::mem::last_scan_ms();
                    VIOLET_INFO("find_references 0x{:X} -> {} ref(s) in {:.1f} ms",
                                address, g_xrefs.size(), g_xref_ms);
                }

                ImGui::PopID();
            }
            ImGui::EndTable();
        }

        if (g_xref_target == 0)
            return;

        heading("Code that references it");

        if (g_xrefs.empty())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
            ImGui::TextWrapped(
                "No RIP-relative reference found. That usually means the string is "
                "reached through a table or a pointer rather than by taking its "
                "address directly - very common for arrays of related strings.");
            ImGui::PopStyleColor();
            return;
        }

        std::snprintf(buf, sizeof(buf), "%zu reference(s) in %.1f ms",
                      g_xrefs.size(), g_xref_ms);
        key_value("found", buf, true);

        ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
        ImGui::TextWrapped("Paste an IDA address below into your disassembler. "
                           "'lea' takes the address, 'mov' loads through it.");
        ImGui::PopStyleColor();

        if (ImGui::BeginTable("##xrefs", 3,
                              ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                              ImGuiTableFlags_ScrollY, { 0.0f, 150.0f }))
        {
            ImGui::TableSetupColumn("instruction");
            ImGui::TableSetupColumn("IDA");
            ImGui::TableSetupColumn("kind", ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();

            ImGui::PushFont(g_font_mono, 0.0f);
            for (const auto& x : g_xrefs)
            {
                const violet::mem::ScanResult r{ x.instruction };
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)x.instruction);
                ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)r.ida());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(x.kind == 'L' ? "lea" : "mov");
            }
            ImGui::PopFont();
            ImGui::EndTable();
        }
    }

    void draw_dump()
    {
        heading("Memory dump");

        ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
        ImGui::TextWrapped(
            "The file on disk has been processed after linking - a disassembler reads "
            "mostly nonsense from it. But by the time Violet is running, the loader has "
            "mapped the image and anything that unpacks has already unpacked, because "
            "the CPU has to execute real instructions eventually. Memory holds the truth.");
        ImGui::PopStyleColor();

        ImGui::Dummy({ 0.0f, 6.0f });

        char buf[192];

        if (ImGui::Button("Compare memory with disk"))
            g_compare = violet::mem::compare_text_with_disk();

        if (g_compare)
        {
            if (!g_compare->ok)
            {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.90f, 0.32f, 0.34f, 1.0f });
                ImGui::TextWrapped("%s", g_compare->detail.c_str());
                ImGui::PopStyleColor();
            }
            else
            {
                std::snprintf(buf, sizeof(buf), "%.2f%% of bytes differ",
                              g_compare->percent);
                key_value("difference", buf, true);

                std::snprintf(buf, sizeof(buf), "%zu of %zu",
                              g_compare->differing, g_compare->compared);
                key_value("bytes", buf, true);

                ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
                ImGui::TextWrapped("%s", g_compare->detail.c_str());
                ImGui::PopStyleColor();
            }
        }

        ImGui::Dummy({ 0.0f, 6.0f });

        if (ImGui::Button("Dump module to disk"))
            g_dump = violet::mem::dump_module();

        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
        ImGui::TextUnformatted("writes ~91 MB, takes a second");
        ImGui::PopStyleColor();

        if (g_dump)
        {
            if (!g_dump->ok)
            {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.90f, 0.32f, 0.34f, 1.0f });
                ImGui::TextWrapped("%s", g_dump->detail.c_str());
                ImGui::PopStyleColor();
            }
            else
            {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.44f, 0.85f, 0.52f, 1.0f });
                ImGui::TextUnformatted("Written.");
                ImGui::PopStyleColor();

                ImGui::PushFont(g_font_mono, 0.0f);
                ImGui::TextWrapped("%s", g_dump->path.c_str());
                ImGui::PopFont();

                ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
                ImGui::TextWrapped("%s", g_dump->detail.c_str());
                ImGui::TextWrapped("Open this in IDA instead of the original. Section headers "
                                   "have been rewritten to describe the mapped layout, and the "
                                   "image base restored to 0x140000000 so every address still "
                                   "matches the live process.");
                ImGui::PopStyleColor();

                if (ImGui::Button("Copy path"))
                    ImGui::SetClipboardText(g_dump->path.c_str());
            }
        }
    }

    void tab_scanner()
    {
        draw_dump();

        heading("Self-test");

        if (!g_selftest)
            g_selftest = violet::mem::self_test();

        const bool passed = g_selftest->passed;
        ImGui::PushStyleColor(ImGuiCol_Text, passed ? ImVec4{ 0.44f, 0.85f, 0.52f, 1.0f }
                                                    : ImVec4{ 0.90f, 0.32f, 0.34f, 1.0f });
        ImGui::PushFont(g_font_bold, 0.0f);
        ImGui::TextUnformatted(passed ? "PASS" : "FAIL");
        ImGui::PopFont();
        ImGui::PopStyleColor();

        ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
        ImGui::TextWrapped("%s", g_selftest->detail.c_str());
        ImGui::PopStyleColor();

        char buf[128];
        const double mb = static_cast<double>(g_selftest->bytes_scanned) / (1024.0 * 1024.0);
        std::snprintf(buf, sizeof(buf), "%.1f MB in %.1f ms", mb, g_selftest->elapsed_ms);
        key_value("swept", buf, true);

        if (g_selftest->elapsed_ms > 0.0)
        {
            std::snprintf(buf, sizeof(buf), "%.0f MB/s", mb / (g_selftest->elapsed_ms / 1000.0));
            key_value("throughput", buf, true);
        }

        // Discovery comes first, then signatures. You cannot write a signature
        // for something you have not found yet.
        draw_find_text();

        heading("Try a signature");

        ImGui::PushStyleColor(ImGuiCol_Text, k_text_dim);
        ImGui::TextWrapped("Once you have located something, a signature is how you find it "
                           "again after a game update. Hex byte pairs, ? for a wildcard - "
                           "wildcard the bytes that move between builds (call offsets, RIP "
                           "displacements) and keep the opcodes.");
        ImGui::PopStyleColor();

        ImGui::Dummy({ 0.0f, 4.0f });

        ImGui::PushFont(g_font_mono, 0.0f);
        ImGui::SetNextItemWidth(-1.0f);
        const bool submitted = ImGui::InputText("##signature", g_sig_input, sizeof(g_sig_input),
                                                ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopFont();

        if (ImGui::Button("Scan") || submitted)
            run_signature_scan();

        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, g_sig_ok ? k_text_dim
                                                      : ImVec4{ 0.90f, 0.32f, 0.34f, 1.0f });
        ImGui::TextWrapped("%s", g_sig_status.c_str());
        ImGui::PopStyleColor();

        if (!g_sig_hits.empty())
        {
            std::snprintf(buf, sizeof(buf), "%zu match(es), %.1f ms, %zu fixed bytes",
                          g_sig_hits.size(), g_sig_ms, g_sig_fixed);
            key_value("result", buf, true);

            if (g_sig_fixed < 6)
            {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.95f, 0.72f, 0.30f, 1.0f });
                ImGui::TextWrapped("Only %zu bytes actually have to match - that is very "
                                   "loose and will hit unrelated code.", g_sig_fixed);
                ImGui::PopStyleColor();
            }

            ImGui::Dummy({ 0.0f, 4.0f });

            // RVA is the durable form; the IDA column can be pasted straight
            // into a disassembler's jump-to-address box.
            if (ImGui::BeginTable("##hits", 3,
                                  ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                                  ImGuiTableFlags_ScrollY,
                                  { 0.0f, 190.0f }))
            {
                ImGui::TableSetupColumn("runtime");
                ImGui::TableSetupColumn("RVA");
                ImGui::TableSetupColumn("IDA");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                ImGui::PushFont(g_font_mono, 0.0f);
                for (const auto address : g_sig_hits)
                {
                    const violet::mem::ScanResult r{ address };
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)address);
                    ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)r.rva());
                    ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)r.ida());
                }
                ImGui::PopFont();
                ImGui::EndTable();
            }
        }
    }

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
    ImGui::SetNextWindowSize({ 620.0f, 640.0f }, ImGuiCond_FirstUseEver);

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

    // The tabs live in a scrolling child so the footer stays pinned.
    //
    // Without this the footer is simply the last thing appended to the window,
    // so the moment a tab's content grew taller than the window the footer -
    // and the Unload button on it - scrolled off the bottom and looked like it
    // had disappeared. Reserving space here and letting the body scroll inside
    // it is the ImGui idiom for a fixed footer.
    const float footer_height = ImGui::GetTextLineHeightWithSpacing()
                              + ImGui::GetFrameHeightWithSpacing()
                              + ImGui::GetStyle().ItemSpacing.y * 2.0f;

    ImGui::BeginChild("##violet_body", { 0.0f, -footer_height });

    if (ImGui::BeginTabBar("##violet_tabs"))
    {
        if (ImGui::BeginTabItem("Status"))
        {
            tab_status(vp);
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Scanner"))
        {
            tab_scanner();
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

    // EndChild is called whether or not BeginChild returned true - unlike
    // Begin/End, it is unconditional.
    ImGui::EndChild();

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

        // On its own line, right-aligned the safe way.
        //
        // Two previous attempts at this were wrong in opposite directions.
        // SetCursorPosX(GetWindowWidth() - width - padding) overshot, because
        // cursor positions already sit inside the padding - the button spilled
        // past the content region, which spawned a horizontal scrollbar, which
        // changed the layout, which moved it back, every frame. Then measuring
        // GetContentRegionAvail() BEFORE calling SameLine() measured the whole
        // next line instead of what was left of the current one, and flung the
        // button off the right edge entirely.
        //
        // On a fresh line the cursor starts at the content origin, so the
        // available width IS the full usable width, and advancing by
        // (available - button width) lands the right edge exactly on the
        // margin. No SameLine, nothing to get out of order.
        const float available = ImGui::GetContentRegionAvail().x;
        if (available > width)
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + available - width);

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
            {
                g_unload_armed  = true;
                g_unload_arm_at = ImGui::GetTime();
            }
        }

        // Disarm on its own after a few seconds. If the first press was a
        // mistake, the second one should not still be waiting for it minutes
        // later on some unrelated click.
        if (g_unload_armed && ImGui::GetTime() - g_unload_arm_at > 4.0)
            g_unload_armed = false;

        ImGui::PopStyleColor(3);

        if (g_unload_armed && ImGui::IsItemHovered())
            ImGui::SetTooltip("Violet will detach from the game.\n"
                              "You can inject a fresh build straight away -\n"
                              "no need to restart GTA.");
    }

    ImGui::End();
}
}
