CLANG ?= clang
GO ?= go
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_SRC := bpf/detector.bpf.c
BPF_OBJ := bpf/detector.bpf.o
VMLINUX := bpf/vmlinux.h

.PHONY: all clean vmlinux bpf build run

all: vmlinux bpf build

# 生成 vmlinux.h
vmlinux: $(VMLINUX)

$(VMLINUX):
	@echo "Generating vmlinux.h..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# 编译 eBPF 程序
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) bpf/detector.h
	@echo "Compiling eBPF program..."
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I./bpf \
		-c $< -o $@

# 编译 Go 程序
build:
	@echo "Building Go program..."
	CGO_ENABLED=1 $(GO) build -o mini-detector ./cmd/mini-detector

# 运行
run: all
	sudo ./mini-detector

# JSON 模式运行
run-json: all
	sudo ./mini-detector --json

# 清理
clean:
	rm -f $(BPF_OBJ) mini-detector
	rm -f $(VMLINUX)

# 帮助
help:
	@echo "Available targets:"
	@echo "  all      - Build everything (default)"
	@echo "  vmlinux  - Generate vmlinux.h"
	@echo "  bpf      - Compile eBPF program"
	@echo "  build    - Build Go program"
	@echo "  run      - Build and run"
	@echo "  run-json - Build and run with JSON output"
	@echo "  clean    - Remove build artifacts"
