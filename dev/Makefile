CC=gcc
CLANG=clang-18
CFLAGS=-O2 -Wall
LIBS=-lOpenCL -lbpf -lpthread

all: asic_main asic_sensor.bpf.o pmc_sensor

asic_main: host/asic_main.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

asic_sensor.bpf.o: sensors/asic_sensor.bpf.c
	$(CLANG) -g -O2 -target bpf -I. -c $< -o $@

pmc_sensor: sensors/pmc_sensor.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f asic_main asic_sensor.bpf.o pmc_sensor
