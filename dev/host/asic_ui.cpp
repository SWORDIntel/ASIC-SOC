#include "imgui.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include <stdio.h>
#define GLEW_STATIC
#include <GL/glew.h>
#include <GLFW/glfw3.h>
#include "asic_telemetry.h"
#include <vector>
#include <string>
#include <algorithm>

static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "Glfw Error %d: %s\n", error, description);
}

extern "C" void* run_ui_thread(void* arg) {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) return NULL;

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1280, 720, "ASI COMMAND CENTER (C++ OVERDRIVE)", NULL, NULL);
    if (window == NULL) return NULL;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    if (glewInit() != GLEW_OK) return NULL;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    ImVec4 clear_color = ImVec4(0.05f, 0.05f, 0.10f, 1.00f);

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        update_telemetry_stats();

        // 1. Header
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, 50));
        ImGuiWindowFlags header_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar;
        ImGui::Begin("Header", NULL, header_flags);
        const char* h_text = g_telemetry.hammer_mode ? "!!! ME HAMMER MODE ACTIVE !!!" : (g_telemetry.jamming_active ? "!!! EMERGENCY: INTERFERENCE !!!" : "ASI COMMAND CENTER");
        ImVec4 h_color = (g_telemetry.hammer_mode || g_telemetry.jamming_active) ? ImVec4(1, 0, 0, 1) : ImVec4(0, 0.5f, 1, 1);
        ImGui::TextColored(h_color, "%s", h_text);
        ImGui::SameLine(io.DisplaySize.x - 200);
        ImGui::Text("SWARM NODES: %d", g_telemetry.swarm_nodes);
        ImGui::End();

        // 2. Vitals
        ImGui::SetNextWindowPos(ImVec2(0, 50));
        ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x / 2, 150));
        ImGui::Begin("System Vitals", NULL, header_flags);
        ImGui::ProgressBar(g_telemetry.host_cpu / 100.0f, ImVec2(-1, 0), "HOST CPU");
        ImGui::ProgressBar(g_telemetry.host_ram / 100.0f, ImVec2(-1, 0), "HOST RAM");
        ImGui::Text("GPU TEMP: %d C", g_telemetry.gpu_temp);
        ImGui::End();

        // 3. ASIC Status
        ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x / 2, 50));
        ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x / 2, 150));
        ImGui::Begin("ASIC Co-Processor", NULL, header_flags);
        ImGui::Text("ASIC CORE: FERMI-QIHSE v3.0 (C++)");
        ImGui::Text("COMPUTE LOAD: %d%%", g_telemetry.asic_load);
        ImGui::Text("TENSOR DB: %d VECTORS (+%d EVOLVED)", g_telemetry.actual_tensors, g_telemetry.tensors_optimized);
        ImGui::ProgressBar(g_telemetry.crypto_corr, ImVec2(-1, 0), "KEY EXTRACTION");
        ImGui::End();

        // 4. Intel Feed
        ImGui::SetNextWindowPos(ImVec2(0, 200));
        ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x * 0.6f, 300));
        ImGui::Begin("ASI Intel Feed");
        if (ImGui::BeginTable("Alerts", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("UTC", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("LAYER", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("MESSAGE");
            ImGui::TableHeadersRow();

            for (int i = 0; i < g_telemetry.alert_count; i++) {
                int idx = (g_telemetry.alert_head - 1 - i + MAX_ALERTS) % MAX_ALERTS;
                asic_alert_t* a = &g_telemetry.alerts[idx];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("%s", a->timestamp);
                ImGui::TableSetColumnIndex(1); 
                if (a->level == 2) ImGui::TextColored(ImVec4(1, 0, 0, 1), "%s", a->layer);
                else if (a->level == 1) ImGui::TextColored(ImVec4(1, 1, 0, 1), "%s", a->layer);
                else ImGui::Text("%s", a->layer);
                ImGui::TableSetColumnIndex(2); ImGui::Text("%s", a->message);
            }
            ImGui::EndTable();
        }
        ImGui::End();

        // 5. Traffic
        ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.6f, 200));
        ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x * 0.4f, 300));
        ImGui::Begin("Traffic Monitor");
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "L1/L2 Stream:");
        for (int i = 0; i < MAX_TRAFFIC_LINES; i++) {
            int idx = (g_telemetry.traffic_head - 1 - i + MAX_TRAFFIC_LINES) % MAX_TRAFFIC_LINES;
            if (g_telemetry.traffic_stream[idx][0]) ImGui::Text("%s", g_telemetry.traffic_stream[idx]);
        }
        ImGui::Separator();
        ImGui::TextColored(ImVec4(1, 1, 0, 1), "L3 ME Stream:");
        for (int i = 0; i < MAX_TRAFFIC_LINES; i++) {
            int idx = (g_telemetry.me_head - 1 - i + MAX_TRAFFIC_LINES) % MAX_TRAFFIC_LINES;
            if (g_telemetry.me_stream[idx][0]) ImGui::Text("%s", g_telemetry.me_stream[idx]);
        }
        ImGui::End();

        // 6. Defense Matrix
        ImGui::SetNextWindowPos(ImVec2(0, 500));
        ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y - 500));
        ImGui::Begin("Defense Matrix");
        ImGui::Columns(4);
        ImGui::Text("L1 EDGE: SECURE"); ImGui::NextColumn();
        ImGui::Text("L2 EDR: %s", g_telemetry.l2_edr_count > 0 ? "IPS ACTIVE" : "ACTIVE"); ImGui::NextColumn();
        ImGui::Text("L3 HW: NOMINAL"); ImGui::NextColumn();
        ImGui::Text("L4 RF: %s", g_telemetry.jamming_active ? "ALERT" : "PASSIVE"); ImGui::NextColumn();
        ImGui::Text("VAULT: %s", g_telemetry.vault_locked ? "LOCKED" : "UNLOCKED"); ImGui::NextColumn();
        ImGui::Text("BLACKBOX: RECORDING");
        ImGui::End();

        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();
    return NULL;
}
