/* Port Tunnel — Win32 tray app + FRP worker (--worker). */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_IE 0x0600
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "builtin.h"
#include "portmap.h"
#include "app_res.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "gdi32.lib")

#define WM_TRAY (WM_APP + 1)
#define WM_REFRESH (WM_APP + 2)
#define ID_TRAY 1
#define ID_TIMER 1
#define IDM_SHOW 1001
#define IDM_START 1002
#define IDM_STOP 1003
#define IDM_EXIT 1004
#define IDM_AUTOSTART 1005
#define IDC_CHK_RDP 2001
#define IDC_EDIT_PORT 2002
#define IDC_BTN_ADD 2003
#define IDC_BTN_START 2004
#define IDC_BTN_STOP 2005
#define IDC_LIST 2006
#define IDC_STATUS 2007
#define IDC_HINT 2008
#define IDC_COPY 2009

static const wchar_t *kRunValueName = L"PortTunnel";

#define MAX_PORTS 32
#define COL_LOCAL 0
#define COL_REMOTE 1
#define COL_POOL 2
#define COL_STATE 3

typedef struct {
    int local;
    int enabled;
    int last_remote;
    int remote;
    int running;
    int ok;
    char error[128];
    PROCESS_INFORMATION pi;
    HANDLE job;
} PortEntry;

typedef struct {
    HWND hwnd;
    HWND list;
    HWND status;
    HWND chk_rdp;
    HWND edit_port;
    NOTIFYICONDATAW nid;
    HICON icon;
    PortEntry ports[MAX_PORTS];
    int nports;
    int mapping_on;
    wchar_t exe_path[MAX_PATH];
    wchar_t data_dir[MAX_PATH];
    HFONT font;
    HFONT font_title;
    HBRUSH bg;
} App;

static App g_app;
static const wchar_t *kCls = L"PortTunnelWnd";
static const wchar_t *kMutex = L"Local\\PortTunnel_SingleInstance";
static int g_start_minimized = 0;

extern int worker_main(int argc, char **argv);

static int autostart_enabled(void) {
    HKEY k = NULL;
    DWORD type = 0, cb = 0;
    LONG rc;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_READ, &k) != ERROR_SUCCESS)
        return 0;
    rc = RegQueryValueExW(k, kRunValueName, NULL, &type, NULL, &cb);
    RegCloseKey(k);
    return rc == ERROR_SUCCESS && type == REG_SZ;
}

static void autostart_set(int enable) {
    HKEY k = NULL;
    wchar_t cmd[MAX_PATH + 32];
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &k) != ERROR_SUCCESS)
        return;
    if (enable) {
        _snwprintf(cmd, MAX_PATH + 32, L"\"%s\" --minimized", g_app.exe_path);
        RegSetValueExW(k, kRunValueName, 0, REG_SZ, (const BYTE *)cmd,
                       (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t)));
    } else {
        RegDeleteValueW(k, kRunValueName);
    }
    RegCloseKey(k);
}

static void utf8_to_wide(const char *s, wchar_t *o, int cap) {
    if (!o || cap < 1) return;
    o[0] = 0;
    if (!s) return;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, o, cap);
}

static void wide_to_utf8(const wchar_t *s, char *o, int cap) {
    if (!o || cap < 1) return;
    o[0] = 0;
    if (!s) return;
    WideCharToMultiByte(CP_UTF8, 0, s, -1, o, cap, NULL, NULL);
}

static void ensure_data_dir(void) {
    wchar_t appdata[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdata))) {
        GetTempPathW(MAX_PATH, appdata);
    }
    _snwprintf(g_app.data_dir, MAX_PATH, L"%s\\PortTunnel", appdata);
    CreateDirectoryW(g_app.data_dir, NULL);
    {
        wchar_t st[MAX_PATH];
        _snwprintf(st, MAX_PATH, L"%s\\status", g_app.data_dir);
        CreateDirectoryW(st, NULL);
    }
}

static void settings_path(wchar_t *out, int cap) {
    _snwprintf(out, cap, L"%s\\settings.json", g_app.data_dir);
}

static void status_path_for(int local, char *out, int cap) {
    char dir[MAX_PATH];
    wide_to_utf8(g_app.data_dir, dir, sizeof(dir));
    snprintf(out, cap, "%s\\status\\%d.json", dir, local);
}

static int find_port(int local) {
    int i;
    for (i = 0; i < g_app.nports; i++)
        if (g_app.ports[i].local == local) return i;
    return -1;
}

static void save_settings(void) {
    wchar_t path[MAX_PATH];
    char upath[MAX_PATH];
    FILE *f;
    int i;
    settings_path(path, MAX_PATH);
    wide_to_utf8(path, upath, sizeof(upath));
    f = fopen(upath, "wb");
    if (!f) return;
    fprintf(f, "{\n  \"mapping_on\": %s,\n  \"ports\": [\n", g_app.mapping_on ? "true" : "false");
    for (i = 0; i < g_app.nports; i++) {
        fprintf(f, "    {\"local\":%d,\"enabled\":%s,\"last_remote\":%d}%s\n",
                g_app.ports[i].local,
                g_app.ports[i].enabled ? "true" : "false",
                g_app.ports[i].last_remote,
                i + 1 < g_app.nports ? "," : "");
    }
    fprintf(f, "  ]\n}\n");
    fclose(f);
}

static int json_get_int_near(const char *s, const char *key, int defv) {
    char pat[64];
    const char *p;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(s, pat);
    if (!p) return defv;
    p = strchr(p + strlen(pat), ':');
    if (!p) return defv;
    return atoi(p + 1);
}

static int json_true_near(const char *s, const char *key) {
    char pat[64];
    const char *p;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(s, pat);
    if (!p) return 0;
    p = strchr(p + strlen(pat), ':');
    if (!p) return 0;
    while (*p == ':' || *p == ' ') p++;
    return strncmp(p, "true", 4) == 0;
}

static void load_settings(void) {
    wchar_t path[MAX_PATH];
    char upath[MAX_PATH], buf[8192];
    FILE *f;
    size_t n;
    const char *p;
    settings_path(path, MAX_PATH);
    wide_to_utf8(path, upath, sizeof(upath));
    g_app.nports = 0;
    g_app.mapping_on = 0;
    /* default: 3389 enabled */
    g_app.ports[0].local = 3389;
    g_app.ports[0].enabled = 1;
    g_app.nports = 1;

    f = fopen(upath, "rb");
    if (!f) return;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);
    g_app.mapping_on = json_true_near(buf, "mapping_on");
    g_app.nports = 0;
    p = buf;
    while ((p = strstr(p, "\"local\"")) != NULL && g_app.nports < MAX_PORTS) {
        PortEntry *e = &g_app.ports[g_app.nports];
        memset(e, 0, sizeof(*e));
        e->local = json_get_int_near(p, "local", 0);
        e->enabled = json_true_near(p, "enabled");
        e->last_remote = json_get_int_near(p, "last_remote", 0);
        if (e->local > 0 && e->local <= 65535) g_app.nports++;
        p += 7;
    }
    if (g_app.nports == 0) {
        g_app.ports[0].local = 3389;
        g_app.ports[0].enabled = 1;
        g_app.nports = 1;
    }
}

static void kill_worker(PortEntry *e) {
    if (e->pi.hProcess) {
        TerminateProcess(e->pi.hProcess, 0);
        CloseHandle(e->pi.hProcess);
        CloseHandle(e->pi.hThread);
        memset(&e->pi, 0, sizeof(e->pi));
    }
    if (e->job) {
        CloseHandle(e->job);
        e->job = NULL;
    }
    e->running = 0;
    e->ok = 0;
    e->remote = 0;
    e->error[0] = 0;
}

static int start_worker(PortEntry *e) {
    wchar_t cmd[1024], status_w[MAX_PATH];
    char status_u[MAX_PATH], name[128], host[64];
    int rmin, rmax, prefer;
    STARTUPINFOW si;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;

    kill_worker(e);
    pt_port_pool(e->local, &rmin, &rmax, &prefer);
    status_path_for(e->local, status_u, sizeof(status_u));
    utf8_to_wide(status_u, status_w, MAX_PATH);
    DeleteFileW(status_w);

    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        gethostname(host, sizeof(host) - 1);
    }
    snprintf(name, sizeof(name), "pt-%s-%d", host, e->local);
    {
        wchar_t wname[128];
        utf8_to_wide(name, wname, 128);
        _snwprintf(cmd, 1024,
                   L"\"%s\" --worker --local %d --rmin %d --rmax %d --prefer %d --last %d --name %s --status \"%s\"",
                   g_app.exe_path, e->local, rmin, rmax, prefer, e->last_remote, wname, status_w);
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    memset(&e->pi, 0, sizeof(e->pi));
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &e->pi)) {
        snprintf(e->error, sizeof(e->error), "启动失败 %lu", (unsigned long)GetLastError());
        return -1;
    }
    e->job = CreateJobObjectW(NULL, NULL);
    if (e->job) {
        memset(&jeli, 0, sizeof(jeli));
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(e->job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
        AssignProcessToJobObject(e->job, e->pi.hProcess);
    }
    e->running = 1;
    snprintf(e->error, sizeof(e->error), "连接中…");
    return 0;
}

static void read_worker_status(PortEntry *e) {
    char path[MAX_PATH], buf[1024];
    FILE *f;
    size_t n;
    if (!e->running) return;
    if (e->pi.hProcess) {
        DWORD code = 0;
        if (GetExitCodeProcess(e->pi.hProcess, &code) && code != STILL_ACTIVE) {
            e->running = 0;
            e->ok = 0;
            if (!e->error[0]) snprintf(e->error, sizeof(e->error), "进程退出");
            return;
        }
    }
    status_path_for(e->local, path, sizeof(path));
    f = fopen(path, "rb");
    if (!f) return;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);
    e->ok = json_true_near(buf, "ok");
    e->remote = json_get_int_near(buf, "remote_port", 0);
    if (e->ok && e->remote > 0) e->last_remote = e->remote;
    {
        const char *p = strstr(buf, "\"error\"");
        e->error[0] = 0;
        if (p) {
            p = strchr(p + 7, '"');
            if (p) {
                const char *q;
                p++;
                q = strchr(p, '"');
                if (q && (size_t)(q - p) < sizeof(e->error)) {
                    memcpy(e->error, p, (size_t)(q - p));
                    e->error[q - p] = 0;
                }
            }
        }
    }
}

static void stop_all(void) {
    int i;
    for (i = 0; i < g_app.nports; i++) kill_worker(&g_app.ports[i]);
    g_app.mapping_on = 0;
    save_settings();
}

static void start_all(void) {
    int i, n = 0;
    for (i = 0; i < g_app.nports; i++) {
        if (!g_app.ports[i].enabled) {
            kill_worker(&g_app.ports[i]);
            continue;
        }
        if (start_worker(&g_app.ports[i]) == 0) n++;
    }
    g_app.mapping_on = n > 0;
    save_settings();
}

static void refresh_list(void) {
    int i;
    wchar_t w[128];
    if (!g_app.list) return;
    SendMessageW(g_app.list, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < g_app.nports; i++) {
        PortEntry *e = &g_app.ports[i];
        int rmin, rmax, prefer;
        LVITEMW it;
        char pool[64], state[160], remote[32];
        pt_port_pool(e->local, &rmin, &rmax, &prefer);
        snprintf(pool, sizeof(pool), "%d-%d", rmin, rmax);
        if (!e->enabled) snprintf(state, sizeof(state), "未启用");
        else if (!e->running) snprintf(state, sizeof(state), "已停止");
        else if (e->ok) snprintf(state, sizeof(state), "已连通");
        else snprintf(state, sizeof(state), "%s", e->error[0] ? e->error : "连接中…");
        if (e->remote > 0) snprintf(remote, sizeof(remote), "%d", e->remote);
        else if (e->last_remote > 0) snprintf(remote, sizeof(remote), "%d*", e->last_remote);
        else snprintf(remote, sizeof(remote), "自动");

        memset(&it, 0, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = i;
        _snwprintf(w, 128, L"%d", e->local);
        it.pszText = w;
        SendMessageW(g_app.list, LVM_INSERTITEMW, 0, (LPARAM)&it);

        utf8_to_wide(remote, w, 128);
        it.iSubItem = COL_REMOTE;
        it.pszText = w;
        SendMessageW(g_app.list, LVM_SETITEMTEXTW, i, (LPARAM)&it);

        utf8_to_wide(pool, w, 128);
        it.iSubItem = COL_POOL;
        SendMessageW(g_app.list, LVM_SETITEMTEXTW, i, (LPARAM)&it);

        utf8_to_wide(state, w, 128);
        it.iSubItem = COL_STATE;
        SendMessageW(g_app.list, LVM_SETITEMTEXTW, i, (LPARAM)&it);
    }
}

static void update_status_bar(void) {
    wchar_t msg[256];
    int ok = 0, run = 0, i;
    for (i = 0; i < g_app.nports; i++) {
        if (g_app.ports[i].running) run++;
        if (g_app.ports[i].ok) ok++;
    }
    if (!g_app.mapping_on)
        _snwprintf(msg, 256, L"服务器 %hs · 未启动", PT_SERVER_ADDR);
    else if (ok == run && run > 0)
        _snwprintf(msg, 256, L"服务器 %hs · 全部连通 (%d)", PT_SERVER_ADDR, ok);
    else
        _snwprintf(msg, 256, L"服务器 %hs · 连通 %d / 运行 %d", PT_SERVER_ADDR, ok, run);
    SetWindowTextW(g_app.status, msg);

    if (g_app.nid.hWnd) {
        wcsncpy(g_app.nid.szTip, msg, 127);
        g_app.nid.szTip[127] = 0;
        Shell_NotifyIconW(NIM_MODIFY, &g_app.nid);
    }
}

static void sync_rdp_checkbox(void) {
    int idx = find_port(3389);
    SendMessageW(g_app.chk_rdp, BM_SETCHECK,
                 (idx >= 0 && g_app.ports[idx].enabled) ? BST_CHECKED : BST_UNCHECKED, 0);
}

static void add_or_enable_port(int local, int enable) {
    int idx = find_port(local);
    if (idx < 0) {
        if (g_app.nports >= MAX_PORTS) return;
        idx = g_app.nports++;
        memset(&g_app.ports[idx], 0, sizeof(g_app.ports[idx]));
        g_app.ports[idx].local = local;
    }
    g_app.ports[idx].enabled = enable ? 1 : 0;
    if (!enable) kill_worker(&g_app.ports[idx]);
    else if (g_app.mapping_on) start_worker(&g_app.ports[idx]);
    save_settings();
    sync_rdp_checkbox();
    refresh_list();
    update_status_bar();
}

static void tray_add(HWND hwnd) {
    memset(&g_app.nid, 0, sizeof(g_app.nid));
    g_app.nid.cbSize = sizeof(g_app.nid);
    g_app.nid.hWnd = hwnd;
    g_app.nid.uID = ID_TRAY;
    g_app.nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_app.nid.uCallbackMessage = WM_TRAY;
    g_app.nid.hIcon = g_app.icon;
    wcsncpy(g_app.nid.szTip, L"Port Tunnel", 127);
    Shell_NotifyIconW(NIM_ADD, &g_app.nid);
}

static void tray_del(void) {
    if (g_app.nid.hWnd) Shell_NotifyIconW(NIM_DELETE, &g_app.nid);
}

static void copy_selected_endpoint(void) {
    int i = (int)SendMessageW(g_app.list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
    char text[128];
    wchar_t w[128];
    HGLOBAL h;
    wchar_t *p;
    if (i < 0 || i >= g_app.nports) return;
    if (g_app.ports[i].remote <= 0) {
        MessageBoxW(g_app.hwnd, L"该端口尚未分配外网端口", L"Port Tunnel", MB_OK | MB_ICONINFORMATION);
        return;
    }
    snprintf(text, sizeof(text), "%s:%d", PT_SERVER_ADDR, g_app.ports[i].remote);
    utf8_to_wide(text, w, 128);
    if (!OpenClipboard(g_app.hwnd)) return;
    EmptyClipboard();
    h = GlobalAlloc(GMEM_MOVEABLE, (wcslen(w) + 1) * sizeof(wchar_t));
    if (h) {
        p = (wchar_t *)GlobalLock(h);
        if (p) {
            wcscpy(p, w);
            GlobalUnlock(h);
            SetClipboardData(CF_UNICODETEXT, h);
        }
    }
    CloseClipboard();
}

static HWND create_label(HWND parent, int id, const wchar_t *text, int x, int y, int cw, int ch) {
    HWND hw = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
                              x, y, cw, ch, parent, (HMENU)(intptr_t)id, GetModuleHandleW(NULL), NULL);
    SendMessageW(hw, WM_SETFONT, (WPARAM)g_app.font, TRUE);
    return hw;
}

static void layout_controls(HWND hwnd) {
    CreateWindowExW(0, L"STATIC", L"Port Tunnel",
                    WS_CHILD | WS_VISIBLE,
                    24, 18, 280, 28, hwnd, NULL, GetModuleHandleW(NULL), NULL);
    /* title font applied in WM_CREATE after create */

    create_label(hwnd, IDC_HINT,
                 L"映射本机 TCP 到公网 · 外网口自动分配（每口 100 候选）· Delete 删除",
                 24, 50, 400, 20);

    g_app.chk_rdp = CreateWindowExW(0, L"BUTTON", L"3389  远程桌面 (RDP)",
                                    WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                    24, 82, 260, 24, hwnd, (HMENU)IDC_CHK_RDP,
                                    GetModuleHandleW(NULL), NULL);
    SendMessageW(g_app.chk_rdp, WM_SETFONT, (WPARAM)g_app.font, TRUE);

    create_label(hwnd, 0, L"添加端口", 24, 118, 80, 20);
    g_app.edit_port = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                      WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_AUTOHSCROLL,
                                      100, 114, 80, 26, hwnd, (HMENU)IDC_EDIT_PORT,
                                      GetModuleHandleW(NULL), NULL);
    SendMessageW(g_app.edit_port, WM_SETFONT, (WPARAM)g_app.font, TRUE);

    CreateWindowExW(0, L"BUTTON", L"添加",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    190, 114, 64, 26, hwnd, (HMENU)IDC_BTN_ADD,
                    GetModuleHandleW(NULL), NULL);

    g_app.list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                 WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                 24, 156, 400, 220, hwnd, (HMENU)IDC_LIST,
                                 GetModuleHandleW(NULL), NULL);
    ListView_SetExtendedListViewStyle(g_app.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    {
        LVCOLUMNW c;
        memset(&c, 0, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH;
        c.pszText = L"本机";
        c.cx = 60;
        SendMessageW(g_app.list, LVM_INSERTCOLUMNW, 0, (LPARAM)&c);
        c.pszText = L"外网";
        c.cx = 70;
        SendMessageW(g_app.list, LVM_INSERTCOLUMNW, 1, (LPARAM)&c);
        c.pszText = L"号段";
        c.cx = 110;
        SendMessageW(g_app.list, LVM_INSERTCOLUMNW, 2, (LPARAM)&c);
        c.pszText = L"状态";
        c.cx = 140;
        SendMessageW(g_app.list, LVM_INSERTCOLUMNW, 3, (LPARAM)&c);
    }
    SendMessageW(g_app.list, WM_SETFONT, (WPARAM)g_app.font, TRUE);

    CreateWindowExW(0, L"BUTTON", L"启动映射",
                    WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                    24, 390, 100, 32, hwnd, (HMENU)IDC_BTN_START,
                    GetModuleHandleW(NULL), NULL);
    CreateWindowExW(0, L"BUTTON", L"全部停止",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    136, 390, 100, 32, hwnd, (HMENU)IDC_BTN_STOP,
                    GetModuleHandleW(NULL), NULL);
    CreateWindowExW(0, L"BUTTON", L"复制外网地址",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    248, 390, 120, 32, hwnd, (HMENU)IDC_COPY,
                    GetModuleHandleW(NULL), NULL);

    g_app.status = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD | WS_VISIBLE,
                                   24, 436, 400, 22, hwnd, (HMENU)IDC_STATUS,
                                   GetModuleHandleW(NULL), NULL);
    SendMessageW(g_app.status, WM_SETFONT, (WPARAM)g_app.font, TRUE);

    {
        HWND c = GetWindow(hwnd, GW_CHILD);
        int first = 1;
        while (c) {
            SendMessageW(c, WM_SETFONT, (WPARAM)(first ? g_app.font_title : g_app.font), TRUE);
            first = 0;
            c = GetWindow(c, GW_HWNDNEXT);
        }
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_LISTVIEW_CLASSES};
        InitCommonControlsEx(&icc);
        g_app.font = CreateFontW(18, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                 DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        g_app.font_title = CreateFontW(26, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
                                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                       DEFAULT_PITCH | FF_SWISS, L"Segoe UI Semibold");
        g_app.bg = CreateSolidBrush(RGB(245, 247, 250));
        layout_controls(hwnd);
        sync_rdp_checkbox();
        refresh_list();
        update_status_bar();
        tray_add(hwnd);
        SetTimer(hwnd, ID_TIMER, 1000, NULL);
        if (g_app.mapping_on) start_all();
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetBkColor(dc, RGB(245, 247, 250));
        SetTextColor(dc, RGB(30, 41, 59));
        return (LRESULT)g_app.bg;
    }
    case WM_ERASEBKGND: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect((HDC)wp, &rc, g_app.bg);
        return 1;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_CHK_RDP: {
            int on = (int)SendMessageW(g_app.chk_rdp, BM_GETCHECK, 0, 0) == BST_CHECKED;
            add_or_enable_port(3389, on);
            break;
        }
        case IDC_BTN_ADD: {
            wchar_t t[32];
            int port;
            GetWindowTextW(g_app.edit_port, t, 32);
            port = _wtoi(t);
            if (port < 1 || port > 65535) {
                MessageBoxW(hwnd, L"请输入 1–65535 的端口", L"Port Tunnel", MB_OK | MB_ICONWARNING);
                break;
            }
            add_or_enable_port(port, 1);
            SetWindowTextW(g_app.edit_port, L"");
            break;
        }
        case IDC_BTN_START:
        case IDM_START:
            start_all();
            refresh_list();
            update_status_bar();
            break;
        case IDC_BTN_STOP:
        case IDM_STOP:
            stop_all();
            refresh_list();
            update_status_bar();
            break;
        case IDC_COPY:
            copy_selected_endpoint();
            break;
        case IDM_SHOW:
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
            break;
        case IDM_AUTOSTART:
            autostart_set(!autostart_enabled());
            break;
        case IDM_EXIT:
            stop_all();
            tray_del();
            DestroyWindow(hwnd);
            break;
        }
        return 0;
    case WM_CONTEXTMENU:
    case WM_TRAY:
        if (lp == WM_RBUTTONUP || lp == WM_CONTEXTMENU) {
            POINT pt;
            HMENU m = CreatePopupMenu();
            GetCursorPos(&pt);
            AppendMenuW(m, MF_STRING, IDM_SHOW, L"打开主窗口");
            AppendMenuW(m, MF_STRING, IDM_START, L"启动映射");
            AppendMenuW(m, MF_STRING, IDM_STOP, L"全部停止");
            AppendMenuW(m, MF_SEPARATOR, 0, NULL);
            AppendMenuW(m, MF_STRING | (autostart_enabled() ? MF_CHECKED : 0),
                        IDM_AUTOSTART, L"开机自启");
            AppendMenuW(m, MF_SEPARATOR, 0, NULL);
            AppendMenuW(m, MF_STRING, IDM_EXIT, L"退出");
            SetForegroundWindow(hwnd);
            TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, NULL);
            DestroyMenu(m);
        } else if (lp == WM_LBUTTONDBLCLK || lp == WM_LBUTTONUP) {
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
        }
        return 0;
    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == IDC_LIST && nh->code == LVN_KEYDOWN) {
            LPNMLVKEYDOWN kd = (LPNMLVKEYDOWN)lp;
            if (kd->wVKey == VK_DELETE) {
                int i = (int)SendMessageW(g_app.list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
                if (i >= 0 && i < g_app.nports) {
                    int local = g_app.ports[i].local;
                    kill_worker(&g_app.ports[i]);
                    if (i < g_app.nports - 1)
                        memmove(&g_app.ports[i], &g_app.ports[i + 1],
                                (size_t)(g_app.nports - i - 1) * sizeof(PortEntry));
                    g_app.nports--;
                    if (local == 3389) sync_rdp_checkbox();
                    save_settings();
                    refresh_list();
                    update_status_bar();
                }
            }
        }
        return 0;
    }
    case WM_TIMER:
        if (g_app.mapping_on) {
            int i;
            for (i = 0; i < g_app.nports; i++)
                if (g_app.ports[i].enabled) read_worker_status(&g_app.ports[i]);
            refresh_list();
            update_status_bar();
            save_settings();
        }
        return 0;
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, ID_TIMER);
        stop_all();
        tray_del();
        if (g_app.font) DeleteObject(g_app.font);
        if (g_app.font_title) DeleteObject(g_app.font_title);
        if (g_app.bg) DeleteObject(g_app.bg);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static int gui_main(void) {
    WNDCLASSEXW wc;
    HWND hwnd;
    MSG msg;
    HANDLE mtx;
    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};

    mtx = CreateMutexW(NULL, TRUE, kMutex);
    if (!mtx || GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND other = FindWindowW(kCls, NULL);
        if (other) {
            ShowWindow(other, SW_SHOW);
            SetForegroundWindow(other);
        }
        return 0;
    }

    InitCommonControlsEx(&icc);
    GetModuleFileNameW(NULL, g_app.exe_path, MAX_PATH);
    ensure_data_dir();
    load_settings();

    g_app.icon = (HICON)LoadImageW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDI_APPICON),
                                   IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
    if (!g_app.icon) g_app.icon = LoadIconW(NULL, IDI_APPLICATION);

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kCls;
    wc.hIcon = g_app.icon;
    wc.hIconSm = g_app.icon;
    RegisterClassExW(&wc);

    hwnd = CreateWindowExW(WS_EX_APPWINDOW, kCls, L"Port Tunnel",
                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                           CW_USEDEFAULT, CW_USEDEFAULT, 460, 520,
                           NULL, NULL, GetModuleHandleW(NULL), NULL);
    g_app.hwnd = hwnd;
    if (g_app.icon) {
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)g_app.icon);
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)g_app.icon);
    }
    ShowWindow(hwnd, g_start_minimized ? SW_HIDE : SW_SHOW);
    UpdateWindow(hwnd);

    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    CloseHandle(mtx);
    return (int)msg.wParam;
}

/* Parse WinMain command line into argc/argv (UTF-8). */
static int split_cmd(char ***argv_out) {
    int argc = 0, i;
    LPWSTR *wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    char **argv;
    if (!wargv) return 0;
    argv = (char **)calloc((size_t)argc + 1, sizeof(char *));
    for (i = 0; i < argc; i++) {
        int n = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);
        argv[i] = (char *)malloc((size_t)n);
        WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, argv[i], n, NULL, NULL);
    }
    LocalFree(wargv);
    *argv_out = argv;
    return argc;
}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR cl, int show) {
    char **argv = NULL;
    int argc, i, is_worker = 0;
    (void)hi;
    (void)hp;
    (void)cl;
    (void)show;
    argc = split_cmd(&argv);
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--worker") == 0) is_worker = 1;
        else if (strcmp(argv[i], "--minimized") == 0) g_start_minimized = 1;
    }
    if (is_worker) {
        int rc = worker_main(argc, argv);
        for (i = 0; i < argc; i++) free(argv[i]);
        free(argv);
        return rc;
    }
    for (i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    return gui_main();
}
