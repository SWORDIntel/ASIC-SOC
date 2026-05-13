CC=gcc
CLANG=clang
CFLAGS=-O2 -Wall -I. -Ihost
LIBS=-lbpf -lpthread -lm

all: asic_main asic_sensor.bpf.o

host/asic_telemetry.o: host/asic_telemetry.c
	$(CC) $(CFLAGS) -c $< -o $@

asic_main: host/asic_main.c host/asic_telemetry.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

asic_sensor.bpf.o: sensors/asic_sensor.bpf.c
	$(CLANG) -g -O2 -target bpf -I. -I/usr/include/x86_64-linux-gnu -c $< -o $@

clean:
	rm -f asic_main asic_sensor.bpf.o host/*.o

test-smoke: all
	cd .. && ./tests/smoke_test.sh

test-policy: all
	cd .. && ./tests/policy_test.sh

test: test-smoke test-policy
