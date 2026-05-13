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

test-replay:
	cd .. && ./tests/replay_validator_test.sh

test-qihse-forwarder:
	cd .. && ./tests/qihse_forwarder_test.sh

validate-systemd:
	@command -v systemd-analyze >/dev/null 2>&1 || { echo "SKIP: systemd-analyze not found"; exit 0; }
	@tmp="$$(mktemp)"; \
	if systemd-analyze verify ../asic-soc.service >"$$tmp" 2>&1; then \
		rm -f "$$tmp"; \
		echo "systemd validation passed"; \
	elif [ ! -e /usr/local/bin/asic-edr ] && \
		grep -q '/usr/local/bin/asic-edr' "$$tmp" && \
		! grep -v -E '^[[:space:]]*$$|/usr/local/bin/asic-edr.*(not executable|No such file or directory)' "$$tmp" >/dev/null 2>&1; then \
		cat "$$tmp"; \
		rm -f "$$tmp"; \
		echo "WARNING: systemd validation only reported missing /usr/local/bin/asic-edr; install the agent before enabling the service."; \
	else \
		cat "$$tmp" >&2; \
		rm -f "$$tmp"; \
		exit 1; \
	fi

validate-logrotate:
	@command -v logrotate >/dev/null 2>&1 || { echo "SKIP: logrotate not found"; exit 0; }
	@state="$$(mktemp)"; \
	trap 'rm -f "$$state"' EXIT; \
	logrotate -d -s "$$state" ../packaging/logrotate/asic-edr

verify-install-local:
	@cd .. && ./packaging/verify-install.sh --dry-run

test-ops:
	@cd .. && ./tests/ops_validation_test.sh

test: test-smoke test-policy test-replay test-qihse-forwarder test-ops
