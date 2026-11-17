# Port Tunnel 设计文档

## 1. 目标

Windows 单机托盘小工具：把本机 TCP 端口经公网 frps 反向映射出去，便于外网访问本机服务（典型：RDP 3389）。

约束：

- 单二进制独立运行（不依赖旁路 json / 外部 frpc）
- frps 连接参数编译进二进制（来源：`C:\code\ssh-bridge`）
- UI 精简：勾选 3389、增删端口、启停、看状态、复制外网地址
- 外网口自动分配；每个本机口固定 100 个候选号段

## 2. 架构

```
┌─────────────────────────────────────────────┐
│ PortTunnel.exe (GUI / 托盘)                 │
│  - 端口列表、启停、状态轮询、设置持久化       │
│  - CreateProcess 拉起同 exe --worker         │
└──────────────────┬──────────────────────────┘
                   │ Job Object (父退出杀子)
                   ▼
┌─────────────────────────────────────────────┐
│ PortTunnel.exe --worker                     │
│  - 内嵌 frpc 协议 (TLS + yamux + AES)       │
│  - Dashboard 查占用 → 选口 → NewProxy       │
│  - 工作连接回连 127.0.0.1:local_port        │
│  - 写 status/<local>.json                   │
└──────────────────┬──────────────────────────┘
                   │ :7321 TLS
                   ▼
            sshbridge.online (frps)
            Dashboard :7322
```

同源实现参考：

- 协议客户端：`EmbeddedAIDevelopmentKit/tunnel` / `ssh-bridge/third_party/eadk-tunnel`
- 内置服务器与凭证：`ssh-bridge` 的 `tunnel_apply_builtin_defaults`

## 3. 目录与模块

| 路径 | 职责 |
|------|------|
| `src/app.c` | WinMain：GUI / 托盘 / 拉起 worker / 设置读写 |
| `src/frp_worker.c` | `--worker`：frp 会话、选口、转发 |
| `src/portmap.c` / `portmap.h` | 本机口 → 外网号段 / prefer |
| `src/builtin.h` | 编译期 frps 地址与凭证 |
| `build.bat` | MinGW 编出 `output/PortTunnel.exe` |
| `output/PortTunnel.exe` | 发布物 |

## 4. 内置连接参数

定义于 `src/builtin.h`（与 ssh-bridge 一致）：

| 项 | 值 |
|----|-----|
| server | `sshbridge.online`（兼容 IP `39.97.234.200`） |
| server_port | `7321` |
| token | 见 `PT_TOKEN` |
| dashboard_port | `7322` |
| dashboard_user | `admin` |
| dashboard_password | 见 `PT_DASHBOARD_PASSWORD` |
| local_host | 固定 `127.0.0.1` |

运行时不提供改服务器 UI；改服务器需改 `builtin.h` 后重编。

## 5. 外网端口规则

实现：`pt_port_pool(local, &min, &max, &prefer)`。

每个本机端口对应 **恰好 100** 个连续外网候选口 `[min, max]`。  
TCP 上限 65535，因此不能使用字面「六位端口」；用「×100 / ×10 整百段 / 折叠」逼近「本机口当前缀」的记忆性。

| 条件 | 号段 | prefer | 示例 |
|------|------|--------|------|
| `L*100+99 ≤ 65535`（L≤654） | `[L*100, L*100+99]` | `L*100` | 22→2200–2299 |
| `L*10+9 ≤ 65535`（约 655–6553） | 含 `L*10` 的整百段 | `L*10` | **3389→33800–33899，prefer 33890** |
| 其余 | `40000+(L%350)*100` 起 100 口 | 段起点 | 8080→43000–43099 |

选口顺序（Dashboard 可用时，worker 内）：

1. `prefer` 空闲  
2. `last_remote` 非 online  
3. `local` 落在号段内且空闲（少见）  
4. 号段内升序第一个 free  
5. 号段内升序回收 offline  
6. NewProxy 冲突则 ban 该口，最多重试 8 次  

Dashboard 不可用时回退：`remote_port` → `local` → `last`（本工具通常不强制 `remote_port`）。

## 6. 进程模型

### 6.1 GUI

- 单实例：`Local\PortTunnel_SingleInstance`
- 窗口类：`PortTunnelWnd`
- 关窗：隐藏到托盘，不退出
- 托盘：左键显示；右键 打开 / 启动 / 停止 / 退出
- 定时器 1s：读各 worker status、刷新列表

### 6.2 Worker

命令行（GUI 生成）：

```text
PortTunnel.exe --worker --local L --rmin A --rmax B --prefer P --last Last
  --name pt-<hostname>-L --status "<APPDATA>\PortTunnel\status\L.json"
```

- `CREATE_NO_WINDOW` 隐藏控制台
- 放入 Job Object，`KILL_ON_JOB_CLOSE`：GUI 退出则 worker 被杀
- `proxy_name`：`pt-<hostname>-<local>`，避免多机冲突

### 6.3 状态文件

路径：`%APPDATA%\PortTunnel\status\<local>.json`

```json
{
  "ok": true,
  "local_port": 3389,
  "remote_port": 33890,
  "remote_addr": ":33890",
  "pick": "prefer 33890",
  "error": "",
  "pid": 12345
}
```

- `ok=true` 且 `remote_port>0`：映射成功  
- `ok=false`：`error` 为连接/选口失败原因（如 `connecting`、`login failed`）

### 6.4 用户设置

路径：`%APPDATA%\PortTunnel\settings.json`

```json
{
  "mapping_on": true,
  "ports": [
    {"local": 3389, "enabled": true, "last_remote": 33890}
  ]
}
```

- 启动时若 `mapping_on=true`，自动 `start_all`
- `last_remote` 供下次优先复用

## 7. UI 行为

| 控件 | 行为 |
|------|------|
| 勾选「3389 远程桌面」 | 启用/停用 3389；若正在映射则即时启停 worker |
| 添加端口 | 输入 1–65535，加入列表并启用 |
| Delete | 删除选中行（含 3389） |
| 启动映射 | 对所有 `enabled` 端口起 worker |
| 全部停止 | 杀全部 worker，`mapping_on=false` |
| 复制外网地址 | 剪贴板写入 `sshbridge.online:<remote_port>` |
| 列表列 | 本机 / 外网 / 号段 / 状态 |

状态文案：`未启用` / `已停止` / `连接中…` / `已连通` / 错误串。

## 8. 协议要点（worker）

与现网 frps 兼容的 frpc 客户端：

1. TCP → TLS1.2+（Schannel）→ yamux  
2. `LOGIN`：`privilege_key = md5(token + timestamp)` 十六进制  
3. 登录成功后 AES（PBKDF2(token,"frp",64)）  
4. Dashboard `GET /api/proxy/tcp` + Basic → 解析 online/offline  
5. `NEW_PROXY`：`proxy_type=tcp`，`remote_port=所选`  
6. `REQ_WORK` → 新 yamux stream → 回连本机 `127.0.0.1:local` 双向拷贝  
7. 断线后约 3s 重连（`stop_flag` 为真则退出）

不映射 UDP；一 worker 一口；多口 = 多 worker 进程。

## 9. 编译

```bat
cd C:\code\tunnel
build.bat
```

依赖：`C:\msys64\mingw64\bin\gcc.exe`  
链接：`ws2_32 secur32 crypt32 bcrypt comctl32 shell32 ole32` 等  
子系统：`-mwindows`  
产物：`output\PortTunnel.exe`

## 10. 安全与边界

- 公网映射等于暴露本机对应端口；RDP 需本机有强密码/NLA
- token / dashboard 密码在二进制内可读；仅用于既有演示 frps
- 号段可能与 ssh-bridge 的 18xxx/28xxx 重叠（如本机 180）；靠 Dashboard 避让 online 口
- 不保证 frps `allowPorts` 策略；若服务端收紧号段，NewProxy 会失败并体现在 status.error
- 本工具不启本机服务，只做转发；3389 需系统已开远程桌面

## 11. 非目标

- 不提供改 frps 的图形配置
- 不内嵌 WebView / 浏览器 UI
- 不做 HTTP/HTTPS 子域名代理
- 不替代 ssh-bridge 整套管理端
