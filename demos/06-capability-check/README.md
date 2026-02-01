# Demo 6: Capability Check - 权限检测

## 学习目标

1. **Linux Capabilities**
   - 替代传统 root 权限
   - 细粒度权限控制

2. **cap_capable 追踪**
   - 内核权限检查核心函数
   - 检测权限提升

## 编译和运行

```bash
cd demos
make demo6
sudo ./06-capability-check/cap_check
```

## 预期输出

```
=============================================================
Demo 6: Capability Check Monitor
=============================================================
TIME     PID     COMM             CAPABILITY
-------------------------------------------------------------
10:30:15 1234    ping             CAP_NET_RAW
10:30:16 5678    docker           CAP_SYS_ADMIN
```

## 核心代码解析

### cap_capable 函数签名

```c
int cap_capable(const struct cred *cred,
                struct user_namespace *ns,
                int cap,
                unsigned int opts);
```

### CAP_OPT_NOAUDIT 过滤

```c
// 跳过探测性检查，减少噪音
if (opts & CAP_OPT_NOAUDIT)
    return 0;
```

## 高危 Capabilities

| Capability | 风险 |
|------------|------|
| CAP_SYS_ADMIN | 几乎等于 root |
| CAP_SYS_MODULE | 加载内核模块 |
| CAP_SYS_PTRACE | 调试任意进程 |
| CAP_NET_RAW | 原始网络访问 |
| CAP_BPF | 加载 BPF 程序 |

**Tracee 参考**: `pkg/ebpf/c/tracee.bpf.c:2530-2549`

## 练习题

1. **权限变更检测**：追踪 commit_creds 检测 UID 变化

2. **容器逃逸检测**：监控容器中的高危 capability

3. **统计分析**：统计各 capability 请求频率
