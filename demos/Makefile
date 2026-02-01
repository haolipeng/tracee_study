# eBPF Learning Demos Makefile
# Reference: libbpf-bootstrap project
#
# Usage:
#   make              - Build all demos
#   make demo1        - Build specific demo (01-hello-exec)
#   make clean        - Clean build artifacts
#   make vmlinux      - Regenerate vmlinux.h

# ============================================================================
# Configuration
# ============================================================================

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
CC ?= gcc

# Architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Directories
COMMON_DIR := common
OUTPUT_DIR := .output

# Compiler flags
INCLUDES := -I$(COMMON_DIR) -I$(OUTPUT_DIR)
CFLAGS := -g -Wall -O2
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# libbpf
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include")
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

# ============================================================================
# Demo Definitions
# ============================================================================

DEMOS := \
	01-hello-exec \
	02-syscall-counter \
	03-process-tree \
	04-file-monitor \
	05-connect-tracker \
	06-capability-check \
	07-mprotect-alert

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean vmlinux $(DEMOS) help

all: $(OUTPUT_DIR) $(DEMOS)
	@echo "✓ All demos built successfully!"
	@echo ""
	@echo "Run demos with sudo, e.g.:"
	@echo "  sudo ./01-hello-exec/hello_exec"

help:
	@echo "eBPF Learning Demos - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build all demos (default)"
	@echo "  demo1     - Build 01-hello-exec"
	@echo "  demo2     - Build 02-syscall-counter"
	@echo "  demo3     - Build 03-process-tree"
	@echo "  demo4     - Build 04-file-monitor"
	@echo "  demo5     - Build 05-connect-tracker"
	@echo "  demo6     - Build 06-capability-check"
	@echo "  demo7     - Build 07-mprotect-alert"
	@echo "  clean     - Remove build artifacts"
	@echo "  vmlinux   - Regenerate vmlinux.h"
	@echo ""
	@echo "Examples:"
	@echo "  make demo1 && sudo ./01-hello-exec/hello_exec"

$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

vmlinux:
	@echo "Generating vmlinux.h from /sys/kernel/btf/vmlinux..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(COMMON_DIR)/vmlinux.h
	@echo "✓ vmlinux.h generated"

# ============================================================================
# Build Rules for Each Demo
# ============================================================================

# Generic build pattern for demos
# $1 = demo directory name
# $2 = base name (e.g., hello_exec)
define BUILD_DEMO

$(1): $(OUTPUT_DIR)
	@echo "Building $(1)..."
	@# Step 1: Compile BPF object
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) \
		-c $(1)/$(2).bpf.c \
		-o $(OUTPUT_DIR)/$(2).bpf.o
	@# Step 2: Generate skeleton header
	$(BPFTOOL) gen skeleton $(OUTPUT_DIR)/$(2).bpf.o > $(OUTPUT_DIR)/$(2).skel.h
	@# Step 3: Compile userspace program
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBBPF_CFLAGS) \
		-I$(OUTPUT_DIR) \
		$(1)/$(2).c \
		-o $(1)/$(2) \
		$(LIBBPF_LDFLAGS)
	@echo "✓ $(1) built: $(1)/$(2)"

endef

# Define build rules for each demo
$(eval $(call BUILD_DEMO,01-hello-exec,hello_exec))
$(eval $(call BUILD_DEMO,02-syscall-counter,syscall_counter))
$(eval $(call BUILD_DEMO,03-process-tree,process_tree))
$(eval $(call BUILD_DEMO,04-file-monitor,file_monitor))
$(eval $(call BUILD_DEMO,05-connect-tracker,connect_tracker))
$(eval $(call BUILD_DEMO,06-capability-check,cap_check))
$(eval $(call BUILD_DEMO,07-mprotect-alert,mprotect_alert))

# Shorthand targets
demo1: 01-hello-exec
demo2: 02-syscall-counter
demo3: 03-process-tree
demo4: 04-file-monitor
demo5: 05-connect-tracker
demo6: 06-capability-check
demo7: 07-mprotect-alert

# ============================================================================
# Clean
# ============================================================================

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OUTPUT_DIR)
	rm -f */hello_exec */syscall_counter */process_tree \
	      */file_monitor */connect_tracker */cap_check */mprotect_alert
	@echo "✓ Clean complete"

# ============================================================================
# Dependencies Check
# ============================================================================

.PHONY: check-deps

check-deps:
	@echo "Checking dependencies..."
	@which $(CLANG) > /dev/null || (echo "ERROR: clang not found" && exit 1)
	@which $(BPFTOOL) > /dev/null || (echo "ERROR: bpftool not found" && exit 1)
	@test -f /sys/kernel/btf/vmlinux || (echo "ERROR: BTF not available" && exit 1)
	@pkg-config --exists libbpf || echo "WARNING: libbpf pkg-config not found"
	@echo "✓ All dependencies available"
