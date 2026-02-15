# Mini eBPF Security Detector

一个简单但功能完整的 eBPF 安全检测工具示例。

## 功能

- 提权检测（监控 UID/EUID 变化为 root）
- 敏感文件访问检测（/etc/shadow、/etc/passwd 等）
- JSON 格式输出
- 白名单过滤

## 环境要求

- Linux 内核 5.8+（需要 Ring Buffer 支持）
- Go 1.19+
- Clang 11+
- libbpf-dev

## 快速开始

```bash
# 1. 安装依赖（Ubuntu/Debian）
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) golang-go

# 2. 编译
make all

# 3. 运行
sudo ./mini-detector

# JSON 输出模式
sudo ./mini-detector --json
```

## 测试

```bash
# 终端 1：运行检测器
sudo ./mini-detector

# 终端 2：触发提权（需要先设置环境）
sudo chmod u+s /usr/bin/find
su - testuser
find /etc/passwd -exec whoami \;

# 终端 2：触发敏感文件访问
cat /etc/shadow
```

## 项目结构

```
mini-detector/
├── bpf/
│   ├── detector.bpf.c      # eBPF 程序
│   ├── detector.h          # 共享数据结构
│   └── vmlinux.h           # 内核类型（编译时生成）
├── pkg/
│   └── detector/
│       ├── detector.go     # 主检测器
│       └── events.go       # 事件定义
├── cmd/
│   └── mini-detector/
│       └── main.go         # 入口
├── Makefile
├── go.mod
└── README.md
```

## 扩展

你可以在此基础上添加更多检测功能：

- 内核模块加载检测
- 网络连接监控
- 进程执行监控
- 容器逃逸检测

参考 [从零搭建教程](../tutorial-ebpf-detector-from-scratch.md) 了解更多。

## 许可证

GPL-2.0
