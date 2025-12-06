# =============================================================================
# Variables
# =============================================================================

# Remote Environment
REMOTE_HOST  := ubuntu@192.168.100.2
REMOTE_DIR   := /opt/mellanox/doca/applications/upf_accel
BUILD_DIR    := /tmp/build
REMOTE_ADDR  := 192.168.100.2:8805
REMOTE_IFACE := tmfifo_net0

# Local Environment
TEST_TOOL_DIR := /home/stanley/free5gc/NFs/upf/testtools/upftest
LOCAL_IP      := 192.168.100.1
LOCAL_IFACE   := tmfifo_net0

# Free5GC Paths
FREE5GC_DIR   := ~/free5gc

# Application Run Command
# Note: Using -l 0-6 for core affinity and specific PCI addresses
APP_CMD := sudo $(BUILD_DIR)/upf_accel/doca_upf_accel -l 0-6 -- -a pci/03:00.0,dv_flow_en=2 -a pci/03:00.1,dv_flow_en=2

# =============================================================================
# Targets
# =============================================================================

.PHONY: all build run test dump dump-remote \
        run-upf stop-upf \
        run-free5gc-core stop-free5gc-core \
        run-5gc stop-5gc \
        test-pcap test-full test-free5gc

all: build

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------

build:
	ssh $(REMOTE_HOST) "export PKG_CONFIG_PATH=/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig:\$$PKG_CONFIG_PATH && cd $(REMOTE_DIR)/.. && rm -rf $(BUILD_DIR) && meson setup $(BUILD_DIR) && ninja -C $(BUILD_DIR)"

# -----------------------------------------------------------------------------
# UPF Management
# -----------------------------------------------------------------------------

# Run UPF interactively
run:
	ssh -t $(REMOTE_HOST) "$(APP_CMD) -f $(REMOTE_DIR)/doca.json -l 60 -p 0"

# Run UPF in background
run-upf:
	ssh $(REMOTE_HOST) "$(APP_CMD) -f $(REMOTE_DIR)/doca.json" > app.log 2>&1 & \
	echo "UPF started in background. Logs in app.log"

stop-upf:
	ssh $(REMOTE_HOST) "sudo pkill -9 doca_upf_accel; sudo rm -rf /var/run/dpdk/*; sudo rm -rf /dev/hugepages/*" || true

# -----------------------------------------------------------------------------
# Free5GC Management
# -----------------------------------------------------------------------------

run-free5gc-core:
	cd $(FREE5GC_DIR) && ./run.sh &

stop-free5gc-core:
	$(FREE5GC_DIR)/force_kill.sh

# -----------------------------------------------------------------------------
# Environment Management (UPF + Free5GC)
# -----------------------------------------------------------------------------

run-5gc: run-upf run-free5gc-core
	@echo "Started UPF and Free5GC Core"

stop-5gc: stop-upf stop-free5gc-core
	@echo "Stopped UPF and Free5GC Core"

# -----------------------------------------------------------------------------
# Testing & Diagnostics
# -----------------------------------------------------------------------------

test:
	cd $(TEST_TOOL_DIR) && go run main.go -s $(REMOTE_ADDR) -n $(LOCAL_IP)

test-pcap:
	ssh $(REMOTE_HOST) "sudo pkill tcpdump" || true
	ssh $(REMOTE_HOST) "sudo tcpdump -i $(REMOTE_IFACE) -U -w - udp port 8805" > test.pcap 2> tcpdump.log & \
	sleep 5; \
	cd $(TEST_TOOL_DIR) && go run main.go -s $(REMOTE_ADDR) -n $(LOCAL_IP); \
	EXIT_CODE=$$?; \
	sleep 15; \
	ssh $(REMOTE_HOST) "sudo pkill tcpdump"; \
	exit $$EXIT_CODE

dump:
	sudo tcpdump -i $(LOCAL_IFACE) -n

dump-remote:
	ssh -t $(REMOTE_HOST) "sudo tcpdump -i $(REMOTE_IFACE) -n"


# -----------------------------------------------------------------------------
# UERANSIM Management
# -----------------------------------------------------------------------------

UERANSIM_BUILD_DIR := ~/UERANSIM/build
UERANSIM_CONFIG_DIR := ~/UERANSIM/config

run-gnb:
	$(UERANSIM_BUILD_DIR)/nr-gnb -c $(UERANSIM_CONFIG_DIR)/free5gc-gnb.yaml > gnb.log 2>&1 & \
	echo "gNB started in background. Logs in gnb.log"

run-ue:
	$(UERANSIM_BUILD_DIR)/nr-ue -c $(UERANSIM_CONFIG_DIR)/free5gc-ue.yaml > ue.log 2>&1 & \
	echo "UE started in background. Logs in ue.log"

stop-ueransim:
	pkill nr-gnb || true
	pkill nr-ue || true

# -----------------------------------------------------------------------------
# Full Integration Tests
# -----------------------------------------------------------------------------

stop-all: stop-5gc stop-ueransim
	ssh $(REMOTE_HOST) "sudo pkill tcpdump" || true
	@echo "Stopped all components"

test-testtools: stop-upf build
	# Start the application in the background
	$(MAKE) run-upf
	APP_PID=$$!; \
	echo "Waiting for application to initialize..."; \
	sleep 10; \
	$(MAKE) test-pcap; \
	EXIT_CODE=$$?; \
	echo "Test finished with exit code $$EXIT_CODE"; \
	$(MAKE) stop-upf; \
	exit $$EXIT_CODE

run-free5gc-test-flow:
	$(MAKE) stop-free5gc-core
	ssh $(REMOTE_HOST) "sudo pkill tcpdump" || true
	ssh $(REMOTE_HOST) "sudo tcpdump -i $(REMOTE_IFACE) -U -w - udp port 8805" > free5gc.pcap 2> tcpdump.log & \
	sleep 5; \
	$(MAKE) run-free5gc-core; \
	EXIT_CODE=$$?; \
	sleep 5; \
	ssh $(REMOTE_HOST) "sudo pkill tcpdump"; \
	echo "Verifying pcap..."; \
	tcpdump -r $(CURDIR)/free5gc.pcap -n; \
	exit $$EXIT_CODE

test-free5gc: stop-upf build
	# Start the application in the background
	$(MAKE) run-upf
	APP_PID=$$!; \
	echo "Waiting for application to initialize..."; \
	sleep 10; \
	$(MAKE) run-free5gc-test-flow; \
	EXIT_CODE=$$?; \
	echo "Test finished with exit code $$EXIT_CODE"; \
	$(MAKE) stop-upf; \
	exit $$EXIT_CODE

test-full: stop-all build
	# 1. Start tcpdump
	ssh $(REMOTE_HOST) "sudo tcpdump -i $(REMOTE_IFACE) -U -w - udp port 2152 or udp port 8805" > test-full.pcap 2> tcpdump.log & \
	echo "Started tcpdump"
	
	# 2. Start UPF
	$(MAKE) run-upf
	echo "Waiting for UPF..."
	sleep 10
	
	# 3. Start Free5GC Core
	$(MAKE) run-free5gc-core
	echo "Waiting for Free5GC..."
	sleep 10
	
	# 4. Start gNB
	$(MAKE) run-gnb
	echo "Waiting for gNB..."
	sleep 5
	
	# 5. Start UE
	$(MAKE) run-ue
	echo "Waiting for UE traffic..."
	sleep 10
	
	# 6. Stop tcpdump
	ssh $(REMOTE_HOST) "sudo pkill tcpdump" || true
	
	# 7. Cleanup
	$(MAKE) stop-all
	
	# 8. Read result
	echo "Verifying pcap..."
	tcpdump -r $(CURDIR)/test-full.pcap -n

