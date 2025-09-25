# Makefile for eBPF TCP Port Dropper

# Detect architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Kernel source directory
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/source
KERNEL_BUILD ?= /lib/modules/$(shell uname -r)/build

# Compiler and flags
CLANG ?= clang
LLC ?= llc
GO ?= go

# eBPF C flags - Updated for compatibility with newer kernels
BPF_CFLAGS := -O2 -target bpf -D__KERNEL__ -D__BPF_TRACING__ -D__TARGET_ARCH_x86 \
	-Wall -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option -Wno-pragma-once-outside-header \
	-Wno-format -Wno-format-security -fno-stack-protector \
	-fno-jump-tables -fno-unwind-tables -fno-asynchronous-unwind-tables

# Simplified include paths to avoid problematic kernel headers
BPF_INCLUDES := -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean install-deps build-bpf build-go run

all: build-bpf build-go

# Install dependencies
install-deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(shell uname -r) gcc-multilib
	$(GO) mod tidy

# Build eBPF program
build-bpf: tcp_drop.o

tcp_drop.o: tcp_drop.c tcp_drop.h
	@echo "Building eBPF program..."
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c tcp_drop.c -o tcp_drop.o
	@echo "eBPF program built successfully!"

# Build Go program
build-go: tcp_drop.o
	@echo "Building Go program..."
	$(GO) build -o tcp-port-dropper main.go

# Run the program (requires sudo)
run: all
	@echo "Running TCP port dropper (requires sudo)..."
	sudo ./tcp-port-dropper

# Clean build artifacts
clean:
	rm -f tcp_drop.o tcp-port-dropper

# Help
help:
	@echo "Available targets:"
	@echo "  all         - Build both eBPF and Go programs"
	@echo "  install-deps- Install required dependencies"
	@echo "  build-bpf   - Build only eBPF program"
	@echo "  build-go    - Build only Go program"
	@echo "  run         - Build and run the program"
	@echo "  clean       - Clean build artifacts"
	@echo "  help        - Show this help message"
