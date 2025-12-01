REMOTE_HOST := ubuntu@192.168.100.2
REMOTE_DIR := /opt/mellanox/doca/applications/upf_accel
BUILD_DIR := /tmp/build
TEST_TOOL_DIR := /home/stanley/free5gc/NFs/upf/testtools/upftest

# Local IP for the test tool to bind/announce
LOCAL_IP := 192.168.100.1
LOCAL_IFACE := tmfifo_net0
# Remote IP:Port for the UPF
REMOTE_ADDR := 192.168.100.2:8805
# Remote Interface
REMOTE_IFACE := tmfifo_net0

.PHONY: all build run test dump dump-remote

all: build

build:
	ssh $(REMOTE_HOST) "export PKG_CONFIG_PATH=/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig:\$$PKG_CONFIG_PATH && cd $(REMOTE_DIR)/.. && rm -rf $(BUILD_DIR) && meson setup $(BUILD_DIR) && ninja -C $(BUILD_DIR)"

run:
	ssh -t $(REMOTE_HOST) "sudo $(BUILD_DIR)/upf_accel/doca_upf_accel -l 0-6 -- -a pci/03:00.0,dv_flow_en=2 -a pci/03:00.1,dv_flow_en=2 -f ~/policy.json"

test:
	cd $(TEST_TOOL_DIR) && go run main.go -s $(REMOTE_ADDR) -n $(LOCAL_IP)

test-pcap:
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

clean-remote:
	ssh $(REMOTE_HOST) "sudo pkill -9 doca_upf_accel; sudo rm -rf /var/run/dpdk/*; sudo rm -rf /dev/hugepages/*" || true

test-full: clean-remote build
	# Start the application in the background
	ssh $(REMOTE_HOST) "sudo $(BUILD_DIR)/upf_accel/doca_upf_accel -l 0-6 -- -a pci/03:00.0,dv_flow_en=2 -a pci/03:00.1,dv_flow_en=2 -f ~/policy.json" > app.log 2>&1 & \
	APP_PID=$$!; \
	echo "Waiting for application to initialize..."; \
	sleep 10; \
	make test-pcap; \
	EXIT_CODE=$$?; \
	echo "Test finished with exit code $$EXIT_CODE"; \
	make clean-remote; \
	exit $$EXIT_CODE
