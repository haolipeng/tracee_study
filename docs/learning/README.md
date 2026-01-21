# Tracee 源代码学习指南

> 欢迎来到 Tracee 源代码深度学习教程！
> 本系列教程将带你从零开始，系统性地理解 Tracee 的设计理念、技术架构和核心实现。

---

## 📖 学习路线图

### 适合人群

- 🎯 **安全工程师**：想要深入理解 eBPF 安全工具的实现原理
- 🛠️ **系统程序员**：希望学习 eBPF 技术在实际项目中的应用
- 📚 **开源贡献者**：准备为 Tracee 项目贡献代码
- 🔍 **技术爱好者**：对 Linux 内核监控和运行时安全感兴趣

### 前置知识

| 必须掌握 | 建议了解 | 可选 |
|---------|---------|------|
| ✅ Linux 系统编程基础 | 💡 eBPF 基本概念 | 🌟 Kubernetes 基础 |
| ✅ Go 语言基础 | 💡 系统调用原理 | 🌟 容器技术 |
| ✅ C 语言基础 | 💡 内核数据结构 | 🌟 安全检测理论 |

---

## 📚 教程目录

### [第一阶段：架构概览](01-architecture-overview.md)
**预计时间**: 2-3 天 | **难度**: ⭐⭐☆☆☆

学习内容：
- ✅ Tracee 是什么，解决什么问题
- ✅ 整体系统架构和分层设计
- ✅ 项目目录结构和核心文件
- ✅ 启动流程和组件初始化
- ✅ Tracee 核心结构体设计

关键收获：
- 理解 "Everything is an Event" 设计理念
- 掌握从 CLI 到 eBPF 的完整数据流
- 了解多层管道架构的优势

---

### [第二阶段：事件处理流水线](02-event-pipeline.md)
**预计时间**: 3-5 天 | **难度**: ⭐⭐⭐☆☆

学习内容：
- ✅ 7 阶段流水线架构详解
- ✅ 事件定义系统和 ID 分类
- ✅ 二进制协议解码机制
- ✅ 事件派生和关联逻辑
- ✅ 容器元数据丰富过程

关键收获：
- 理解 Decode → Sort → Process → Enrich → Derive → Engine → Sink 流程
- 掌握事件对象池等性能优化技巧
- 学会自定义事件处理器和派生器

---

### [第三阶段：eBPF 内核侧实现](03-ebpf-implementation.md)
**预计时间**: 4-7 天 | **难度**: ⭐⭐⭐⭐☆

学习内容：
- ✅ eBPF 程序结构和组织方式
- ✅ 系统调用拦截和 tail call 机制
- ✅ LSM hook 的使用
- ✅ Perf Buffer 数据传输原理
- ✅ BPF Maps 的设计和操作
- ✅ 多级过滤架构

关键收获：
- 理解 sys_enter/sys_exit 拦截点
- 掌握 LSM hook 与系统调用的区别
- 学会设计高效的 BPF Maps
- 理解内核态过滤的性能优势

---

### 第四阶段：Go 用户空间实现
**预计时间**: 3-5 天 | **难度**: ⭐⭐⭐☆☆

**注意**：本阶段文档待创建，以下为内容大纲

学习内容：
- 事件解码器详细实现
- 进程树管理机制
- 容器信息获取和缓存
- DNS 缓存工作原理
- 符号表管理

推荐阅读文件：
- `pkg/bufferdecoder/decoder.go`
- `pkg/proctree/proctree.go`
- `pkg/containers/containers.go`
- `pkg/dnscache/dnscache.go`

---

### 第五阶段：策略与检测引擎
**预计时间**: 3-4 天 | **难度**: ⭐⭐⭐⭐☆

**注意**：本阶段文档待创建，以下为内容大纲

学习内容：
- 策略 YAML 解析
- 策略管理器实现
- Scope 和 Event 过滤
- 签名引擎架构
- 自定义签名开发

推荐阅读文件：
- `pkg/policy/policy_manager.go`
- `pkg/filters/filters.go`
- `pkg/signatures/engine/engine.go`
- `signatures/golang/examples/example.go`

---

### 第六阶段：容器感知与集成
**预计时间**: 2-3 天 | **难度**: ⭐⭐⭐☆☆

**注意**：本阶段文档待创建，以下为内容大纲

学习内容：
- CGroup 管理和检测
- 容器运行时适配 (Docker/containerd/CRI-O)
- Kubernetes 元数据获取
- 容器路径解析
- 容器符号加载

推荐阅读文件：
- `pkg/containers/containers.go`
- `pkg/k8s/client.go`
- `common/cgroup/cgroups.go`

---

## 🎯 学习建议

### 1. 循序渐进

```
第一周：阶段1-2  →  理解整体架构和事件流
第二周：阶段3    →  深入 eBPF 内核实现
第三周：阶段4-5  →  用户空间和策略引擎
第四周：阶段6    →  容器集成和实践项目
```

### 2. 动手实践

每个阶段都包含实践练习，**强烈建议**：
- ✅ 运行所有示例代码
- ✅ 完成每个练习题
- ✅ 尝试修改源代码并观察效果
- ✅ 使用调试工具 (bpftool, strace, gdb)

### 3. 边学边记

建议创建学习笔记：
```bash
mkdir ~/tracee-learning-notes
cd ~/tracee-learning-notes

# 为每个阶段创建笔记
touch stage1-notes.md
touch stage2-notes.md
# ...
```

记录内容包括：
- 🔍 难以理解的概念和解决方法
- 💡 关键代码片段的个人注释
- 🐛 遇到的问题和解决方案
- ✨ 有趣的发现和优化思路

### 4. 参与社区

- 📢 [GitHub Discussions](https://github.com/aquasecurity/tracee/discussions) - 提问和讨论
- 💬 [Slack](https://slack.aquasec.com) - 实时交流
- 🐞 [Issue Tracker](https://github.com/aquasecurity/tracee/issues) - 报告问题

---

## 🛠️ 开发环境搭建

### 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/aquasecurity/tracee.git
cd tracee

# 2. 检查环境
make env

# 3. 编译所有组件
make all

# 4. 运行测试
make test-unit

# 5. 首次运行
sudo ./dist/tracee --help
sudo ./dist/tracee -e execve
```

### 推荐工具

| 工具 | 用途 | 安装命令 |
|------|------|---------|
| **bpftool** | eBPF 程序调试 | `apt install linux-tools-generic` |
| **bpftrace** | 动态跟踪脚本 | `apt install bpftrace` |
| **strace** | 系统调用跟踪 | `apt install strace` |
| **perf** | 性能分析 | `apt install linux-tools-common` |
| **delve** | Go 调试器 | `go install github.com/go-delve/delve/cmd/dlv@latest` |

---

## 📊 学习路径图

```
┌─────────────────────────────────────────────────────────────┐
│                 Tracee 学习路径图                            │
└─────────────────────────────────────────────────────────────┘

  开始
   │
   ▼
┌──────────────────┐
│ 第一阶段：架构   │  → 理解整体设计
│ (2-3天) ⭐⭐      │     运行基本示例
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 第二阶段：流水线 │  → 理解事件流
│ (3-5天) ⭐⭐⭐     │     自定义处理器
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 第三阶段：eBPF   │  → 内核态编程
│ (4-7天) ⭐⭐⭐⭐    │     添加自定义探针
└────────┬─────────┘
         │
         ├─────────────────────┐
         │                     │
         ▼                     ▼
┌──────────────────┐   ┌──────────────────┐
│ 第四阶段：用户空间│   │ 第五阶段：策略   │
│ (3-5天) ⭐⭐⭐     │   │ (3-4天) ⭐⭐⭐⭐    │
└────────┬─────────┘   └────────┬─────────┘
         │                      │
         └──────────┬───────────┘
                    │
                    ▼
          ┌──────────────────┐
          │ 第六阶段：容器   │
          │ (2-3天) ⭐⭐⭐     │
          └────────┬─────────┘
                   │
                   ▼
          ┌──────────────────┐
          │  完整项目实践    │
          │  • 添加新事件    │
          │  • 编写签名规则  │
          │  • 性能优化      │
          └──────────────────┘
                   │
                   ▼
               贡献代码！
```

---

## 📖 推荐阅读顺序

### 核心文件阅读清单

| 优先级 | 文件 | 阶段 | 建议用时 |
|--------|------|------|---------|
| 🔥🔥🔥 | `cmd/tracee/main.go` | 1 | 15min |
| 🔥🔥🔥 | `pkg/cmd/tracee.go` | 1 | 30min |
| 🔥🔥🔥 | `pkg/ebpf/tracee.go` | 1 | 1h |
| 🔥🔥🔥 | `pkg/ebpf/events_pipeline.go` | 2 | 1h |
| 🔥🔥🔥 | `pkg/events/core.go` | 2 | 1.5h |
| 🔥🔥🔥 | `pkg/ebpf/c/tracee.bpf.c` | 3 | 3h+ |
| 🔥🔥 | `pkg/bufferdecoder/decoder.go` | 2 | 1h |
| 🔥🔥 | `pkg/policy/policy_manager.go` | 5 | 1h |
| 🔥🔥 | `pkg/containers/containers.go` | 6 | 1h |
| 🔥 | `pkg/proctree/proctree.go` | 4 | 45min |

**总计**：约 **15-20 小时**核心代码阅读时间

---

### [调试指南](debugging-guide.md)
**预计时间**: 1-2 天 | **难度**: ⭐⭐☆☆☆

学习内容：
- ✅ 使用 Delve 调试 Go 用户态代码
- ✅ Tracee 日志系统配置和使用
- ✅ 使用 bpftool 和 bpftrace 调试 eBPF 程序
- ✅ 常见问题排查（程序加载失败、事件丢失、性能问题）
- ✅ pprof 和 Pyroscope 性能分析
- ✅ 内存泄漏检测

关键收获：
- 掌握完整的调试工具链
- 能够定位和解决开发中的常见问题
- 学会性能分析和优化方法

---

## 🎓 进阶主题

完成基础学习后，可以探索以下高级主题：

### 性能优化
- Per-CPU 数据结构设计
- 零拷贝技术应用
- 事件批处理优化
- 内存池管理

### 高级 eBPF 技术
- CO-RE (Compile Once, Run Everywhere)
- BTF (BPF Type Format)
- BPF 程序链接和库
- Ring Buffer vs Perf Buffer

### 安全检测
- MITRE ATT&CK 映射
- 行为分析算法
- 威胁情报集成
- 机器学习应用

### 生产部署
- 大规模部署策略
- 监控和告警
- 性能调优
- 故障排查

---

## 🤝 贡献指南

学习过程中发现文档问题？欢迎贡献！

```bash
# 1. Fork 仓库
gh repo fork aquasecurity/tracee

# 2. 创建分支
git checkout -b docs/improve-learning-guide

# 3. 修改文档
vim docs/learning/*.md

# 4. 提交 PR
git commit -am "docs: improve learning guide clarity"
git push origin docs/improve-learning-guide
gh pr create
```

---

## 📞 获取帮助

遇到问题？有多种方式获取帮助：

1. **搜索文档**：[官方文档](https://aquasecurity.github.io/tracee/)
2. **GitHub Issues**：查找类似问题或提出新问题
3. **Discussions**：参与社区讨论
4. **Slack**：实时交流

---

## 📚 参考资源

### 官方资源
- [Tracee 官方文档](https://aquasecurity.github.io/tracee/)
- [Tracee GitHub](https://github.com/aquasecurity/tracee)
- [eBPF 官方网站](https://ebpf.io/)

### 学习资源
- [BPF Performance Tools](http://www.brendangregg.com/bpf-performance-tools-book.html) - Brendan Gregg
- [Linux Observability with BPF](https://www.oreilly.com/library/view/linux-observability-with/9781492050193/)
- [eBPF 开发实践教程](https://github.com/eunomia-bpf/bpf-developer-tutorial)

### 相关项目
- [libbpfgo](https://github.com/aquasecurity/libbpfgo) - Tracee 使用的 Go eBPF 库
- [cilium/ebpf](https://github.com/cilium/ebpf) - 另一个流行的 Go eBPF 库
- [Falco](https://falco.org/) - 类似的运行时安全项目

---

## 🎉 开始学习

准备好了吗？让我们从第一阶段开始：

👉 **[第一阶段：架构概览](01-architecture-overview.md)**

祝学习愉快！🚀

---

_最后更新：2025-10-10_
_维护者：Tracee 社区_
_许可证：Apache 2.0_
