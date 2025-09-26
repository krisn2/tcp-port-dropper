# Makefile for eBPF TCP Port Dropper

# Detect architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Kernel source directory (for reference, not explicitly used in this simplified build)
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/source
KERNEL_BUILD ?= /lib/modules/$(shell uname -r)/build

# Compiler and flags
CLANG ?= clang
GO ?= go

# CFLAGS: Includes -g for BPF Type Format (BTF) generation, fixing the load error.
CFLAGS := -g -O2 -target bpf -D__KERNEL__ -D__BPF_TRACING__ -D__TARGET_ARCH_x86 -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -Wno-pragma-once-outside-header -Wno-format -Wno-format-security -fno-stack-protector -fno-jump-tables -fno-unwind-tables -fno-asynchronous-unwind-tables -I/usr/include -I/usr/include/x86_64-linux-gnu

# Simplified include paths (BPF_INCLUDES removed as CFLAGS provides necessary paths)

.PHONY: all clean install-deps run help

all: tcp_drop.o build-go

# =============================================================
# Build Dependencies
# =============================================================

install-deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	# Installing kernel tools is crucial for 'llvm-strip' and headers for compilation
	sudo apt-get install -y clang llvm libbpf-dev linux-tools-$(shell uname -r) linux-headers-$(shell uname -r)
	$(GO) mod tidy

# =============================================================
# Build eBPF Program (tcp_drop.o)
# =============================================================

tcp_drop.o: tcp_drop.c tcp_drop.h
	@echo "Building eBPF program..."
	# Compile C code with CFLAGS (includes -g for debug info)
	$(CLANG) $(CFLAGS) -c tcp_drop.c -o tcp_drop.o
	
	# Strip debug info and embed BTF data (FIX for 'missing BTF' error)
	@if command -v llvm-strip &> /dev/null; then \
		llvm-strip --strip-debug --strip-unneeded tcp_drop.o; \
	else \
		echo "Warning: llvm-strip not found. BTF may be missing."; \
	fi
	@echo "eBPF program built successfully!"

# =============================================================
# Build Go Program (tcp-port-dropper)
# =============================================================

build-go: tcp_drop.o
	@echo "Building Go program..."
	$(GO) build -o tcp-port-dropper main.go

# =============================================================
# Run Target
# =============================================================

# Default run target (requires sudo and assumes lo interface and port 8080 for a quick local test)
run: all
	@echo "Running TCP port dropper on 'lo' interface, port 8080 (requires sudo)..."
	@echo "Use 'sudo ./tcp-port-dropper -iface <interface> -port <port>' for custom args."
	sudo ./tcp-port-dropper -iface lo -port 8080

# =============================================================
# Clean Target
# =============================================================

clean:
	@echo "Cleaning build artifacts..."
	rm -f tcp_drop.o tcp-port-dropper

# =============================================================
# Help Target
# =============================================================

help:
	@echo "Available targets:"
	@echo "  all           - Build both eBPF and Go programs"
	@echo "  install-deps  - Install required dependencies (IMPORTANT!)"
	@echo "  run           - Build and run the program on 'lo:8080'"
	@echo "  build-go      - Build only Go program"
	@echo "  clean         - Clean build artifacts"
