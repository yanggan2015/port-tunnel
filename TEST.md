# Port Tunnel 测试文档

供人工或其它 Agent 按条执行。产物：`C:\code\tunnel\output\PortTunnel.exe`。

## 0. 准备

```bat
cd C:\code\tunnel
build.bat
```

- 需要：`C:\msys64\mingw64\bin\gcc.exe`、`windres`
- 编过应出现 `output\PortTunnel.exe`
- 测前结束已有进程：`Stop-Process -Name PortTunnel -Force -ErrorAction SilentlyContinue`
- 可清设置：删 `%APPDATA%\PortTunnel\`（可选）

设计说明见 `DESIGN.md`。

---

## 1. 端口池单测（不连网）

```bat
gcc -O2 -o output\portmap_test.exe src\portmap.c -x c - << 用临时 main 或内联
```

更简单：在临时文件中 `#include "portmap.h"` 调 `pt_port_pool`，期望：

| local | min–max | prefer |
|------:|---------|-------:|
| 22 | 2200–2299 | 2200 |
| 80 | 8000–8099 | 8000 |
| 443 | 44300–44399 | 44300 |
| **3389** | **33800–33899** | **33890** |
| 8080 | 43000–43099 | 43000 |
| 65535 | 48500–48599 | 48500 |

每段长度必须为 100（`max-min+1==100`）。

---

## 2. Worker 连通（不启 GUI）

```powershell
$dir = "$env:TEMP\pt-test"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$st = "$dir\3389.json"
$p = Start-Process .\output\PortTunnel.exe -ArgumentList @(
  "--worker","--local","3389","--rmin","33800","--rmax","33899",
  "--prefer","33890","--name","pt-agent-test-3389","--status",$st
) -PassThru -WindowStyle Hidden
Start-Sleep 10
Get-Content $st
Stop-Process -Id $p.Id -Force
```

**通过标准：**

- 存在 status JSON
- `"ok":true`
- `"remote_port"` 在 33800–33899（优先 33890）
- `"pick"` 含 `prefer` / `free` / `last` 之一
- `"error":""`

失败常见：`login failed`、`connect frps failed`、`no port in …`（网络或 frps 不可用）。

---

## 3. GUI 基础

1. 启动 `PortTunnel.exe`，窗口标题 **Port Tunnel**，有自定义图标（非系统默认）
2. 默认勾选 **3389 远程桌面**，列表有一行本机 3389、号段 33800–33899
3. 点 **启动映射**，约 10s 内状态变 **已连通**，外网列有端口号
4. 选中该行 → **复制外网地址** → 剪贴板为 `sshbridge.online:<端口>`
5. **全部停止** → 状态变已停止；`%APPDATA%\PortTunnel\status\3389.json` 进程应退出
6. 关窗 → 窗口隐藏，托盘图标仍在；托盘左键再打开
7. 托盘右键：**打开主窗口 / 启动映射 / 全部停止 / 开机自启 / 退出**

---

## 4. 端口增删

1. 添加端口 `18080`（或其它未占用），列表出现，号段符合 `pt_port_pool`
2. 已启动映射时，新启用端口应自动起 worker 并最终连通（或给出 error）
3. 选中行按 `Delete` → 行消失；若删 3389，复选框应变未勾选
4. 再勾选 3389 → 行回来

---

## 5. 开机自启

1. 托盘勾选 **开机自启**
2. 检查注册表：

```powershell
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run | Select PortTunnel
```

应类似：`"C:\...\PortTunnel.exe" --minimized`

3. 取消勾选 → 该项删除
4. （可选）手动执行 `PortTunnel.exe --minimized` → 只进托盘不弹主窗

---

## 6. 单实例

1. 已运行时再开一次 exe → 不应出现第二进程常驻；应激活已有窗口
2. `Get-Process PortTunnel` 主 GUI 通常 1 个（另有 worker 子进程，映射开启时）

---

## 7. 持久化

1. 启用若干端口并启动映射，连通后退出（托盘退出）
2. 看 `%APPDATA%\PortTunnel\settings.json`：`mapping_on`、各 `local`/`enabled`/`last_remote`
3. 再启动 → 应按 `mapping_on` 自动恢复映射，并尽量复用 `last_remote`

---

## 8. 回归清单（打勾）

- [ ] `build.bat` 成功
- [ ] 端口池表数值正确
- [ ] worker 3389 → ok + 3389x 端口
- [ ] GUI 启停 / 复制地址
- [ ] 添加 / Delete 端口
- [ ] 托盘与关窗隐藏
- [ ] 开机自启勾选写注册表
- [ ] 单实例
- [ ] settings.json 恢复

## 不测范围

- 真实 RDP 登录（需本机开远程桌面 + 账号）
- 改 frps 地址（需改 `builtin.h` 重编）
- Linux / macOS
