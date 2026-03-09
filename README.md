
# QIHSE SECURITY ASIC & ASI COMMAND CENTER (v3.2-MONOLITH)
**Hardware-Accelerated Defense & AI Autonomous Research Bodyguard**

## 1. Executive Summary
The **QIHSE Security ASIC** transforms legacy NVIDIA GPUs into dedicated security co-processors. Version 3.2 introduces a **High-Fidelity Vector GUI** and a split-architecture model, separating root-level sensor enforcement from user-level visualization. The system now integrates with **Karpathy's Autoresearch** to provide hardware-accelerated semantic ranking and data preparation.

## 2. Multi-Layer Defense Matrix (L1 - L6)
The system monitors and protects the entire silicon-to-signal spectrum:

| Layer | Domain | Technology | Core Engine | Tactical Action |
| :--- | :--- | :--- | :--- | :--- |
| **L1** | **EDGE** | Multi-XDP Sensor | **QIHSE Superposition** | **Active IP Blocking** (IPS Mode) |
| **L2** | **EDR/CFP** | eBPF Syscall Hooks | **QIHSE Vector Search** | **Automated Process Termination** |
| **L2+** | **CODE** | inotify C-Bridge | **Context Core** | **AI Intent Verification** & Secret Scanning |
| **L3** | **HARDWARE**| PMC Cache Sensor | **Entropy Analyzer** | Side-Channel (Spectre) Mitigation |
| **L3+** | **ME/CSME** | PCI HECI Link | **Sentry Core** | **ME Payload Interception** (L3+ Sentry) |
| **L4** | **SYSTEM** | eBPF RAM Guard | **Resource Monitor** | **Active OOM Prevention** (70% Threshold) |
| **L5** | **SANDBOX** | eBPF Clean Room | **Sandbox Core** | **Secure Execution** of Dev Builds |
| **L6** | **CRYPTO** | Side-Channel DPA | **Berserker Core** | Long-term Intel ME Key Extraction |

## 3. Advanced Technical Features (v3.2)
- **Split-Architecture GUI**: 
  - **`asic_daemon` (Root)**: High-performance心 heart handling eBPF, OpenCL, and PCI-level ME monitoring.
  - **`asic_gui` (User)**: High-fidelity Dear ImGui vector interface. Zero-ghosting, flicker-free rendering via **Stroboscopic Seqlock** atomic snapshots.
- **High-Precision Telemetry Bus**: Uses a hard-aligned 64-bit memory map and high-precision delta-polling from `/proc/stat` to eliminate data jitter.
- **Aggressive VRAM Relief**: Proactively offloads large host-side buffers (codebase indices, embeddings) into GPU VRAM when system RAM usage exceeds 70%.
- **Dynamic Behavioral Safe-List**: Automatically identifies and graduates safe development processes (Windsurf, Gemini) to a "Safe Tier" based on clean operational history.
- **Dual-GPU Acceleration**: Simultaneous utilization of **GTX 560 Ti** (Compute) and **G210** (UI/Telemetry Offload).

## 4. Autonomous Research Integration
The ASIC now supports hardware-offloading for **Karpathy's Autoresearch**:
- **Search/Ranking**: Utilizes `qihse_vector_search` for hyperparameter optimization and experiment ranking.
- **Data Prep**: Offloads document hashing and deduplication to the **Integrity Core**.
- **Semantic Sync**: Accelerates BPE tokenization and semantic vector bit-projection.

## 5. Tactical Dashboard
The v3.2 interface provides a "Medical/Automotive" grade tactical overview:
- **Modular Viewports**: Three primary domains (System Core, ASIC Performance, Code Intelligence).
- **Neon-Glow Vector Borders**: High-visibility status indicators for EDR and ME Sentry.
- **Real-Time Sparklines**: High-resolution history for CPU, RAM, and GPU compute loads.

## 6. CLI Tools & IPC
| Tool | Function | IPC Path |
| :--- | :--- | :--- |
| **asic_daemon** | Root-level co-processor driver. | `/asic_gui_v3_shm` |
| **asic_gui** | High-fidelity tactical dashboard. | `/asic_gui_v3_shm` |
| **asic_intent** | Dispatches NLP instructions to the AI Verifier. | `/tmp/asic_intent_pipe` |
| **asic_secure_run** | Wraps a process in the ASIC eBPF Sandbox. | `/tmp/asic_sandbox_pipe` |

## 7. Quick Start
```bash
# 1. Build the v3.2 Monolith
make clean && make -j$(nproc)

# 2. Launch the Driver (Root)
sudo ./asic_daemon enp4s0 wlp2s0

# 3. Launch the Tactical Command Center (User)
./asic_gui
```

## 8. License
Licensed under the **Hostile Architecture Public License (HAPL) v1.0**. 
Commercial exploitation and AI training on this codebase are strictly prohibited.

---
**Developed by SWORDIntel / DSMIL System**
