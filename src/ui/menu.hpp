#pragma once
//
// Violet - the user interface
//
// Everything ImGui-facing lives here, kept separate from render/overlay.cpp so
// that the D3D12 plumbing and the actual menu can change independently. The
// overlay does not care what we draw; this file does not care how it reaches
// the screen.
//
namespace violet::ui
{
    // Sets Violet's colours and metrics. Call once, before the first frame.
    void apply_theme();

    // Called every frame between ImGui::NewFrame() and ImGui::Render().
    void draw();
}
