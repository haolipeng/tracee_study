# Demo 7: Mprotect Alert - 内存保护告警

## 学习目标

1. **W^X (Write XOR Execute)**
   - 安全原则：内存不应同时可写可执行
   - 违规检测

2. **mprotect 追踪**
   - 内存保护变更检测
   - JIT 编译检测

3. **Git Commit `3ac936c9`**
   - Golang 堆检测精度修复

## 编译和运行

```bash
cd demos
make demo7
sudo ./07-mprotect-alert/mprotect_alert
```

## 预期输出

```
=============================================================
Demo 7: Memory Protection Alert (W^X Violation Detection)
=============================================================
TIME     ALERT      PID     COMM             ADDRESS        PROT
-------------------------------------------------------------
10:30:15 MPROT_+X   1234    node             0x7f1234000000 -W- -> R-X
10:30:16 MMAP_W+X   5678    malware          0x7f5678000000 --- -> RWX
```

## 告警类型

| 类型 | 描述 | 风险等级 |
|------|------|----------|
| MMAP_W+X | mmap 创建 W+X 内存 | 高 |
| MPROT_+WX | mprotect 添加 W+X | 高 |
| MPROT_+X | mprotect 添加 X | 中 (可能是 JIT) |
| MPROT_-W | mprotect 移除 W 保留 X | 低 (正常 JIT) |

## 核心代码解析

### W^X 检测

```c
statfunc bool is_wx_violation(unsigned long prot)
{
    return (prot & PROT_WRITE) && (prot & PROT_EXEC);
}
```

### Git Commit `3ac936c9` 学习

**问题**：Golang 堆检测范围不够精确

```c
// 修复前：简单相等检查
return (vm_start & MASK) == HINT;

// 修复后：范围检查
return (vm_start & MASK) >= HINT &&
       (vm_start & MASK) <= HINT_MAX;
```

## 与 Tracee 对比

| 特性 | Demo | Tracee |
|------|------|--------|
| W^X 检测 | 基础 | + 详细分类 |
| JIT 识别 | 无 | Golang/V8 识别 |
| 内存捕获 | 无 | 可选捕获内容 |

**Tracee 参考**: `pkg/ebpf/c/tracee.bpf.c:3534-3779`

## 练习题

1. **JIT 白名单**：识别并过滤合法的 JIT 编译 (node, java)

2. **内存捕获**：在检测到可疑内存时捕获其内容

3. **进程关联**：结合 execve 追踪，关联可疑内存的程序来源
