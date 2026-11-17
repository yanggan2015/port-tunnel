# Port Tunnel 设计文档

## 1. 目标

Windows 托盘小工具：把本机 **TCP/UDP** 端口经公网 frps 反向映射，便于外网访问本机服务（典型：RDP 3389）。

约束：

- 单二进制独立运行
- frps 参数编译进二进制（来自 ssh-bridge）
- 常用协议勾选 + 自定义端口；开机自启；托盘常驻
- 外网口自动分配；每本机口 100 候选 + 可选记忆 prefer

## 2. 架构

```
PortTunnel.exe (GUI/托盘)
  └─ CreateProcess 同 exe --worker × N（一口一进程，Job Object 联杀）
       └─ TLS+yamux frpc → sshbridge.online:7321
            Dashboard :7322 选口（/api/proxy/tcp|udp）
```

## 3. 外网端口规则（重要）

| 本机 L | 主池（100 口，互不重叠） | prefer（可跨主池） |
|--------|--------------------------|-------------------|
| 1–654 | `[L×100, L×100+99]` | `L×100` |
| ≥655 | `50000+(L%150)×100` 起 100 口 | `L×10`（若≤65535） |

例：

- 22 → 池 2200–2299，prefer 2200  
- **3389 → 池 50xxx（唯一槽），prefer 33890（好记，优先抢）**  
- 338 → 池 33800–33899（与 3389 不再撞车）

选口顺序：prefer（可跨段）→ last → 主池 free → offline 回收 → NewProxy 冲突重试≤8。

## 4. 进程与状态

- Worker：`--worker --local --proto tcp|udp --rmin --rmax --prefer --last --name --status`
- 状态文件：`%APPDATA%\PortTunnel\status\<port>_<tcp|udp>.json`
- 设置：`%APPDATA%\PortTunnel\settings.json`（含 proto / last_remote / label）
- GUI 约 1s 读 status；约 3s 探测本机 `127.0.0.1:port`（TCP connect / UDP bind 占用）

## 5. UI 状态语义

| 文案 | 含义 |
|------|------|
| 已连通 | 公网映射成功且本机端口有服务 |
| 公网通·本机无服务 | frps 已通，但本机端口连不上（常见：未开远程桌面） |
| 连接中… / 错误串 | 登录或选口未完成 |

敏感端口（RDP/SSH/SMB/DB 等）启用前弹确认。

## 6. 安全边界

- 映射＝暴露本机端口；凭证在二进制内可读（演示 frps）
- 不启本机服务，只转发
- 不保证 frps `allowPorts`；冲突靠 Dashboard + 重试

## 7. 已知取舍（非缺陷则不改）

- 一口一 TLS 会话：实现简单、隔离好；多口时连接数线性增加
- UDP 按会话表转发（≤64），适合 DNS 等；长连接 VPN 可用但非专门优化
- 不提供改 frps 的图形配置（改 `builtin.h` 重编）

## 8. 编译

```bat
build.bat
```

产物：`output\PortTunnel.exe`
