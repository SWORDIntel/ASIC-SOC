
CC=gcc
CXX=g++
FC=gfortran
CLANG=clang-18
CFLAGS=-O2 -Wall -I. -Ihost
CXXFLAGS=-O2 -Wall -I. -Ihost -I3rdparty/imgui -I3rdparty/imgui/backends
FFLAGS=-O3 -march=native -ffast-math
LIBS=-lOpenCL -lbpf -lpthread -lm -lpci -lgfortran
GUI_LIBS=-lGL -lGLEW -lglfw

IMGUI_DIR = 3rdparty/imgui
IMGUI_OBJS = $(IMGUI_DIR)/imgui.o $(IMGUI_DIR)/imgui_draw.o $(IMGUI_DIR)/imgui_widgets.o \
             $(IMGUI_DIR)/imgui_tables.o $(IMGUI_DIR)/imgui_demo.o \
             $(IMGUI_DIR)/backends/imgui_impl_glfw.o $(IMGUI_DIR)/backends/imgui_impl_opengl3.o

all: asic_main asic_sensor.bpf.o pmc_sensor

$(IMGUI_DIR)/%.o: $(IMGUI_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(IMGUI_DIR)/backends/%.o: $(IMGUI_DIR)/backends/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

host/qihse_hpc.o: host/qihse_hpc.f90
	$(FC) $(FFLAGS) -c $< -o $@

host/asic_telemetry.o: host/asic_telemetry.c
	$(CC) $(CFLAGS) -c $< -o $@

host/asic_ui.o: host/asic_ui.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

asic_main: host/asic_main.c host/qihse_telemetry.c host/qihse_hpc.o host/asic_telemetry.o host/asic_ui.o $(IMGUI_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS) $(GUI_LIBS)

asic_sensor.bpf.o: sensors/asic_sensor.bpf.c
	$(CLANG) -g -O2 -target bpf -I. -c $< -o $@

pmc_sensor: sensors/pmc_sensor.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f asic_main asic_sensor.bpf.o pmc_sensor host/*.o $(IMGUI_DIR)/*.o $(IMGUI_DIR)/backends/*.o
