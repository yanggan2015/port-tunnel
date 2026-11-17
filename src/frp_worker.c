/* Port Tunnel FRP worker (from EADK tunnel). TLS + yamux. */
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "builtin.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

#define TYPE_LOGIN 'o'
#define TYPE_LOGIN_RESP '1'
#define TYPE_NEW_PROXY 'p'
#define TYPE_NEW_PROXY_RESP '2'
#define TYPE_NEW_WORK 'w'
#define TYPE_REQ_WORK 'r'
#define TYPE_START_WORK 's'
#define TYPE_PING 'h'
#define TYPE_PONG '4'
#define TYPE_UDP_PACKET 'u'

#define Y_DATA 0
#define Y_WND 1
#define Y_PING 2
#define Y_GOAWAY 3
#define Y_SYN 1
#define Y_ACK 2
#define Y_RST 8
#define Y_INIT_WIN (256 * 1024)
#define Y_RECV_MAX (6 * 1024 * 1024)

typedef struct {
    char server_addr[128];
    int server_port;
    char token[128];
    char dashboard_addr[128];
    int dashboard_port;
    char dashboard_user[64];
    char dashboard_password[128];
    char local_host[128];
    int local_port;
    int remote_port;       /* current chosen / forced */
    int last_remote_port;  /* persisted after success */
    int prefer_remote;     /* memorable pick, e.g. 33890 for 3389 */
    int remote_port_min;
    int remote_port_max;
    char proxy_name[64];
    char proxy_type[8]; /* "tcp" or "udp" */
    int http_port;
    char http_bind[64];
    char base_path[64];
    char cfg_path[260];
    char status_path[260];
    char run_id[64];
    char remote_addr[128];
    char last_error[256];
    char pick_reason[128];
    volatile int frp_ok;
    volatile LONG reconnect; /* set to force frp_session exit */
    volatile LONG stop_flag;
    CRITICAL_SECTION mu;
} Cfg;

static Cfg g;

static void write_status_file(void);

#define PORT_SET_MAX 512
typedef struct {
    int n;
    int v[PORT_SET_MAX];
} PortSet;

static int port_set_has(const PortSet *s, int p) {
    int i;
    for (i = 0; i < s->n; i++) if (s->v[i] == p) return 1;
    return 0;
}
static void port_set_add(PortSet *s, int p) {
    if (p <= 0 || port_set_has(s, p) || s->n >= PORT_SET_MAX) return;
    s->v[s->n++] = p;
}

static void b64_encode(const unsigned char *in, int in_len, char *out, int out_cap) {
    static const char *T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, o = 0;
    if (!out || out_cap < 1) return;
    out[0] = 0;
    while (i < in_len) {
        int rem = in_len - i;
        unsigned a = in[i++];
        unsigned b = rem > 1 ? in[i++] : 0;
        unsigned c = rem > 2 ? in[i++] : 0;
        unsigned v = (a << 16) | (b << 8) | c;
        if (o + 4 >= out_cap) break;
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = rem > 1 ? T[(v >> 6) & 63] : '=';
        out[o++] = rem > 2 ? T[v & 63] : '=';
    }
    if (o < out_cap) out[o] = 0;
}

static int b64_decode(const char *in, unsigned char *out, int out_cap) {
    static const signed char T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
    int val = 0, valb = -8, o = 0;
    const unsigned char *p;
    if (!in || !out || out_cap < 0) return -1;
    for (p = (const unsigned char *)in; *p; p++) {
        int d;
        if (*p == '=' || *p == '\r' || *p == '\n' || *p == ' ' || *p == '\t') break;
        d = T[*p];
        if (d < 0) return -1;
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            if (o >= out_cap) return -1;
            out[o++] = (unsigned char)((val >> valb) & 0xff);
            valb -= 8;
        }
    }
    return o;
}

static void set_err(const char *s) {
    EnterCriticalSection(&g.mu);
    snprintf(g.last_error, sizeof(g.last_error), "%s", s ? s : "");
    LeaveCriticalSection(&g.mu);
    write_status_file();
}

static uint32_t md5_rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static void md5(const uint8_t *msg, size_t len, uint8_t out[16]) {
    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
    static const int S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
    uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;
    size_t new_len = len + 1;
    while (new_len % 64 != 56) new_len++;
    uint8_t *b = (uint8_t *)calloc(new_len + 8, 1);
    if (!b) return;
    memcpy(b, msg, len);
    b[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    memcpy(b + new_len, &bits, 8);
    for (size_t off = 0; off < new_len; off += 64) {
        uint32_t w[16];
        memcpy(w, b + off, 64);
        uint32_t a = h0, bb = h1, c = h2, d = h3;
        for (int i = 0; i < 64; i++) {
            uint32_t f, gv;
            if (i < 16) { f = (bb & c) | (~bb & d); gv = (uint32_t)i; }
            else if (i < 32) { f = (d & bb) | (~d & c); gv = (uint32_t)((5 * i + 1) % 16); }
            else if (i < 48) { f = bb ^ c ^ d; gv = (uint32_t)((3 * i + 5) % 16); }
            else { f = c ^ (bb | ~d); gv = (uint32_t)((7 * i) % 16); }
            uint32_t t = d;
            d = c; c = bb;
            bb = bb + md5_rol(a + f + K[i] + w[gv], S[i]);
            a = t;
        }
        h0 += a; h1 += bb; h2 += c; h3 += d;
    }
    free(b);
    memcpy(out, &h0, 4); memcpy(out + 4, &h1, 4); memcpy(out + 8, &h2, 4); memcpy(out + 12, &h3, 4);
}

static void auth_key(const char *token, int64_t ts, char out[33]) {
    char raw[256];
    uint8_t dig[16];
    snprintf(raw, sizeof(raw), "%s%lld", token ? token : "", (long long)ts);
    md5((const uint8_t *)raw, strlen(raw), dig);
    for (int i = 0; i < 16; i++) sprintf(out + i * 2, "%02x", dig[i]);
    out[32] = 0;
}

static int send_all(SOCKET s, const char *buf, int n) {
    int off = 0;
    while (off < n) {
        int w = send(s, buf + off, n - off, 0);
        if (w <= 0) return -1;
        off += w;
    }
    return 0;
}

static void json_get(const char *body, const char *key, char *dst, size_t cap) {
    char pat[64];
    const char *p, *e;
    if (!body || !key || !dst || !cap) return;
    dst[0] = 0;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(body, pat);
    if (!p) return;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':') p++;
    if (*p != '"') return;
    p++;
    e = strchr(p, '"');
    if (!e) return;
    if ((size_t)(e - p) >= cap) return;
    memcpy(dst, p, (size_t)(e - p));
    dst[e - p] = 0;
}

static SOCKET tcp_connect(const char *host, int port);

static int json_get_int(const char *body, const char *key, int defv) {
    char pat[64];
    const char *p;
    if (!body || !key) return defv;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(body, pat);
    if (!p) return defv;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':') p++;
    if (*p == '"') {
        p++;
        return atoi(p);
    }
    if (*p == '-' || (*p >= '0' && *p <= '9')) return atoi(p);
    return defv;
}

/* Fetch dashboard body into *out (malloc). Returns 0 on HTTP 200. */
static int http_get_text(const char *host, int port, const char *path,
                         const char *basic_user, const char *basic_pass,
                         char **out, int *out_len) {
    SOCKET s;
    char req[1024], hdr[256], *buf = NULL;
    int cap = 0, n = 0, total = 0, hdr_done = 0, status = 0;
    char *body = NULL;
    *out = NULL;
    if (out_len) *out_len = 0;
    s = tcp_connect(host, port);
    if (s == INVALID_SOCKET) return -1;
    {
        DWORD ms = 5000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, sizeof(ms));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&ms, sizeof(ms));
    }
    hdr[0] = 0;
    if (basic_user && basic_user[0]) {
        char raw[256], b64[400];
        snprintf(raw, sizeof(raw), "%s:%s", basic_user, basic_pass ? basic_pass : "");
        b64_encode((const unsigned char *)raw, (int)strlen(raw), b64, (int)sizeof(b64));
        snprintf(hdr, sizeof(hdr), "Authorization: Basic %s\r\n", b64);
    }
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n%s\r\n",
             path, host, hdr);
    if (send_all(s, req, (int)strlen(req)) != 0) { closesocket(s); return -1; }
    for (;;) {
        char tmp[4096];
        int r = recv(s, tmp, (int)sizeof(tmp), 0);
        if (r <= 0) break;
        if (total + r + 1 > cap) {
            int ncap = cap ? cap * 2 : 16384;
            char *nb;
            while (ncap < total + r + 1) ncap *= 2;
            nb = (char *)realloc(buf, (size_t)ncap);
            if (!nb) { free(buf); closesocket(s); return -1; }
            buf = nb; cap = ncap;
        }
        memcpy(buf + total, tmp, (size_t)r);
        total += r;
        buf[total] = 0;
        if (!hdr_done) {
            char *sep = strstr(buf, "\r\n\r\n");
            if (sep) {
                hdr_done = 1;
                if (strncmp(buf, "HTTP/", 5) == 0) {
                    const char *sp = strchr(buf, ' ');
                    if (sp) status = atoi(sp + 1);
                }
                body = sep + 4;
                n = total - (int)(body - buf);
            }
        } else {
            n = total - (int)(body - buf);
        }
    }
    closesocket(s);
    if (!hdr_done || status != 200 || !body) { free(buf); return -1; }
    {
        char *nb = (char *)malloc((size_t)n + 1);
        if (!nb) { free(buf); return -1; }
        memcpy(nb, body, (size_t)n);
        nb[n] = 0;
        free(buf);
        *out = nb;
        if (out_len) *out_len = n;
    }
    return 0;
}

static const char *proxy_api_path(void) {
    return strcmp(g.proxy_type, "udp") == 0 ? "/api/proxy/udp" : "/api/proxy/tcp";
}

/* Parse /api/proxy/tcp or /api/proxy/udp JSON into online/offline remotePort sets. */
static void parse_proxy_tcp(const char *json, PortSet *online, PortSet *offline) {
    const char *p = json;
    online->n = 0;
    offline->n = 0;
    if (!json) return;
    while ((p = strstr(p, "\"status\"")) != NULL) {
        const char *st, *chunk0, *chunk1;
        char status[16];
        int port = 0;
        const char *q;
        st = p;
        p += 8;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':') p++;
        status[0] = 0;
        if (*p == '"') {
            p++;
            q = strchr(p, '"');
            if (q && (size_t)(q - p) < sizeof(status)) {
                memcpy(status, p, (size_t)(q - p));
                status[q - p] = 0;
                p = q + 1;
            }
        }
        chunk0 = st - 800;
        if (chunk0 < json) chunk0 = json;
        chunk1 = st + 800;
        if (chunk1 > json + strlen(json)) chunk1 = json + strlen(json);
        {
            char win[1601];
            size_t wlen = (size_t)(chunk1 - chunk0);
            if (wlen > sizeof(win) - 1) wlen = sizeof(win) - 1;
            memcpy(win, chunk0, wlen);
            win[wlen] = 0;
            port = json_get_int(win, "remotePort", 0);
        }
        if (port <= 0) continue;
        if (strcmp(status, "online") == 0) port_set_add(online, port);
        else if (strcmp(status, "offline") == 0) port_set_add(offline, port);
    }
}

static int port_in_range(int p) {
    return p >= g.remote_port_min && p <= g.remote_port_max;
}

static int pick_remote_port(const PortSet *online, const PortSet *offline, int *chosen, char *reason, size_t rcap) {
    int p;
    PortSet busy;
    busy.n = 0;
    for (p = 0; p < online->n; p++) port_set_add(&busy, online->v[p]);
    for (p = 0; p < offline->n; p++) port_set_add(&busy, offline->v[p]);

    /* prefer 可跨主池（如 3389→33890，主池在 50xxx）；last 同理若仍空闲 */
    if (g.prefer_remote > 0 && g.prefer_remote <= 65535 && !port_set_has(&busy, g.prefer_remote)) {
        *chosen = g.prefer_remote;
        snprintf(reason, rcap, "prefer %d", *chosen);
        return 0;
    }
    if (g.last_remote_port > 0 && g.last_remote_port <= 65535 &&
        !port_set_has(online, g.last_remote_port)) {
        *chosen = g.last_remote_port;
        snprintf(reason, rcap, "last_remote_port %d", *chosen);
        return 0;
    }
    if (g.local_port > 0 && port_in_range(g.local_port) && !port_set_has(&busy, g.local_port)) {
        *chosen = g.local_port;
        snprintf(reason, rcap, "same_as_local %d", *chosen);
        return 0;
    }
    for (p = g.remote_port_min; p <= g.remote_port_max; p++) {
        if (!port_set_has(&busy, p)) {
            *chosen = p;
            snprintf(reason, rcap, "free %d", *chosen);
            return 0;
        }
    }
    for (p = g.remote_port_min; p <= g.remote_port_max; p++) {
        if (port_set_has(offline, p) && !port_set_has(online, p)) {
            *chosen = p;
            snprintf(reason, rcap, "offline_reclaim %d", *chosen);
            return 0;
        }
    }
    snprintf(reason, rcap, "no port in %d-%d", g.remote_port_min, g.remote_port_max);
    return -1;
}

static void write_status_file(void) {
    FILE *f;
    if (!g.status_path[0]) return;
    f = fopen(g.status_path, "wb");
    if (!f) return;
    EnterCriticalSection(&g.mu);
    fprintf(f,
            "{\"ok\":%s,\"local_port\":%d,\"remote_port\":%d,\"remote_addr\":\"%s\","
            "\"pick\":\"%s\",\"error\":\"%s\",\"pid\":%lu}\n",
            g.frp_ok ? "true" : "false", g.local_port, g.remote_port, g.remote_addr,
            g.pick_reason, g.last_error, (unsigned long)GetCurrentProcessId());
    LeaveCriticalSection(&g.mu);
    fclose(f);
}

static int dashboard_pick_port(int *chosen) {
    char host[128], *body = NULL, reason[128];
    PortSet online, offline;
    int rc;
    snprintf(host, sizeof(host), "%s",
             g.dashboard_addr[0] ? g.dashboard_addr : g.server_addr);
    if (g.dashboard_port <= 0) {
        if (g.remote_port > 0) {
            *chosen = g.remote_port;
            snprintf(g.pick_reason, sizeof(g.pick_reason), "cfg remote_port");
            return 0;
        }
        if (g.local_port > 0) {
            *chosen = g.local_port;
            snprintf(g.pick_reason, sizeof(g.pick_reason), "cfg local_port (no dashboard)");
            return 0;
        }
        if (g.last_remote_port > 0) {
            *chosen = g.last_remote_port;
            snprintf(g.pick_reason, sizeof(g.pick_reason), "cfg last_remote_port");
            return 0;
        }
        snprintf(g.pick_reason, sizeof(g.pick_reason), "no port (no dashboard)");
        return -1;
    }
    if (http_get_text(host, g.dashboard_port, proxy_api_path(),
                      g.dashboard_user, g.dashboard_password, &body, NULL) != 0) {
        free(body);
        if (g.remote_port > 0) {
            *chosen = g.remote_port;
            snprintf(g.pick_reason, sizeof(g.pick_reason), "dashboard fail -> remote_port");
            return 0;
        }
        if (g.local_port > 0) {
            *chosen = g.local_port;
            snprintf(g.pick_reason, sizeof(g.pick_reason), "dashboard fail -> local_port");
            return 0;
        }
        if (g.last_remote_port > 0) {
            *chosen = g.last_remote_port;
            snprintf(g.pick_reason, sizeof(g.pick_reason), "dashboard fail -> last %d", *chosen);
            return 0;
        }
        snprintf(g.pick_reason, sizeof(g.pick_reason), "dashboard fail, no port");
        return -1;
    }
    parse_proxy_tcp(body, &online, &offline);
    free(body);
    rc = pick_remote_port(&online, &offline, chosen, reason, sizeof(reason));
    snprintf(g.pick_reason, sizeof(g.pick_reason), "%s", reason);
    return rc;
}

static int save_cfg_file(void) {
    FILE *f;
    const char *path = g.cfg_path[0] ? g.cfg_path : "tunnel_config.json";
    f = fopen(path, "wb");
    if (!f) return -1;
    fprintf(f,
            "{\n"
            "  \"eadk\": { \"tool\": \"tunnel\" },\n"
            "  \"server_addr\": \"%s\",\n"
            "  \"server_port\": %d,\n"
            "  \"token\": \"%s\",\n"
            "  \"dashboard_addr\": \"%s\",\n"
            "  \"dashboard_port\": %d,\n"
            "  \"dashboard_user\": \"%s\",\n"
            "  \"dashboard_password\": \"%s\",\n"
            "  \"local_host\": \"%s\",\n"
            "  \"local_port\": %d,\n"
            "  \"remote_port\": %d,\n"
            "  \"last_remote_port\": %d,\n"
            "  \"remote_port_min\": %d,\n"
            "  \"remote_port_max\": %d,\n"
            "  \"proxy_name\": \"%s\",\n"
            "  \"http_port\": %d,\n"
            "  \"http_bind\": \"%s\",\n"
            "  \"base_path\": \"%s\"\n"
            "}\n",
            g.server_addr, g.server_port, g.token,
            g.dashboard_addr, g.dashboard_port, g.dashboard_user, g.dashboard_password,
            g.local_host, g.local_port, g.remote_port, g.last_remote_port,
            g.remote_port_min, g.remote_port_max, g.proxy_name,
            g.http_port, g.http_bind, g.base_path);
    fclose(f);
    return 0;
}

static SOCKET tcp_connect(const char *host, int port) {
    char ps[16];
    struct addrinfo hints, *res = NULL, *rp;
    SOCKET s = INVALID_SOCKET;
    snprintf(ps, sizeof(ps), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0) return INVALID_SOCKET;
    for (rp = res; rp; rp = rp->ai_next) {
        int one = 1;
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
        if (connect(s, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return s;
}

/* ---- TLS + yamux ---- */
#define MAX_STREAMS 32

typedef struct {
    uint32_t id;
    int used;
    int reset;
    int fin;
    int send_win;
    int crypt;
    int enc_ready;
    int dec_ready;
    uint8_t enc_next[16], enc_ks[16];
    int enc_used;
    uint8_t dec_next[16], dec_ks[16];
    int dec_used;
    char *buf;
    int len;
    int cap;
    HANDLE ev;
} YStream;

typedef struct {
    SOCKET sock;
    CredHandle cred;
    CtxtHandle ctx;
    int ctx_ok;
    int cred_ok;
    SecPkgContext_StreamSizes sz;
    CRITICAL_SECTION io;
    CRITICAL_SECTION mu;
    char *enc;
    int enc_len, enc_cap;
    char *plain;
    int plain_len, plain_cap;
    YStream streams[MAX_STREAMS];
    uint32_t next_id;
    volatile LONG dead;
    volatile LONG refs;
    HANDLE reader;
    BCRYPT_ALG_HANDLE aes_alg;
    BCRYPT_KEY_HANDLE aes;
} Mux;

static void yhdr(uint8_t h[12], uint8_t type, uint16_t flags, uint32_t sid, uint32_t len) {
    h[0] = 0; h[1] = type;
    h[2] = (uint8_t)(flags >> 8); h[3] = (uint8_t)flags;
    h[4] = (uint8_t)(sid >> 24); h[5] = (uint8_t)(sid >> 16);
    h[6] = (uint8_t)(sid >> 8); h[7] = (uint8_t)sid;
    h[8] = (uint8_t)(len >> 24); h[9] = (uint8_t)(len >> 16);
    h[10] = (uint8_t)(len >> 8); h[11] = (uint8_t)len;
}

static int buf_grow(char **b, int *cap, int need) {
    if (*cap >= need) return 0;
    int ncap = *cap ? *cap : 4096;
    while (ncap < need) ncap *= 2;
    char *n = (char *)realloc(*b, (size_t)ncap);
    if (!n) return -1;
    *b = n; *cap = ncap;
    return 0;
}

static int tls_send_locked(Mux *m, const void *data, int n) {
    int total = (int)m->sz.cbHeader + n + (int)m->sz.cbTrailer;
    char *b = (char *)malloc((size_t)total);
    SecBuffer bufs[4];
    SecBufferDesc desc;
    SECURITY_STATUS ss;
    int outn;
    if (!b) return -1;
    memcpy(b + m->sz.cbHeader, data, (size_t)n);
    memset(bufs, 0, sizeof(bufs));
    bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
    bufs[0].pvBuffer = b;
    bufs[0].cbBuffer = m->sz.cbHeader;
    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].pvBuffer = b + m->sz.cbHeader;
    bufs[1].cbBuffer = (unsigned)n;
    bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
    bufs[2].pvBuffer = b + m->sz.cbHeader + n;
    bufs[2].cbBuffer = m->sz.cbTrailer;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 4;
    desc.pBuffers = bufs;
    ss = EncryptMessage(&m->ctx, 0, &desc, 0);
    if (ss != SEC_E_OK) { free(b); return -1; }
    outn = (int)bufs[0].cbBuffer + (int)bufs[1].cbBuffer + (int)bufs[2].cbBuffer;
    if (send_all(m->sock, b, outn) != 0) { free(b); return -1; }
    free(b);
    return 0;
}

static int mux_send_raw(Mux *m, const void *data, int n) {
    int rc;
    if (m->dead) return -1;
    EnterCriticalSection(&m->io);
    rc = tls_send_locked(m, data, n);
    LeaveCriticalSection(&m->io);
    return rc;
}

static int tls_decrypt(Mux *m) {
    while (m->enc_len > 0) {
        SecBuffer bufs[4];
        SecBufferDesc desc;
        SECURITY_STATUS ss;
        int i, extra = 0;
        char *data = NULL;
        int data_n = 0;
        memset(bufs, 0, sizeof(bufs));
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].pvBuffer = m->enc;
        bufs[0].cbBuffer = (unsigned)m->enc_len;
        for (i = 1; i < 4; i++) bufs[i].BufferType = SECBUFFER_EMPTY;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = bufs;
        ss = DecryptMessage(&m->ctx, &desc, 0, NULL);
        if (ss == SEC_E_INCOMPLETE_MESSAGE) return 0;
        if (ss != SEC_E_OK) return -1;
        for (i = 0; i < 4; i++) {
            if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer && bufs[i].pvBuffer) {
                data = (char *)bufs[i].pvBuffer;
                data_n = (int)bufs[i].cbBuffer;
            } else if (bufs[i].BufferType == SECBUFFER_EXTRA && bufs[i].cbBuffer && bufs[i].pvBuffer) {
                extra = (int)bufs[i].cbBuffer;
            }
        }
        if (data_n > 0) {
            if (buf_grow(&m->plain, &m->plain_cap, m->plain_len + data_n) != 0) return -1;
            memcpy(m->plain + m->plain_len, data, (size_t)data_n);
            m->plain_len += data_n;
        }
        if (extra > 0) {
            memmove(m->enc, m->enc + m->enc_len - extra, (size_t)extra);
            m->enc_len = extra;
        } else {
            m->enc_len = 0;
        }
    }
    return 0;
}

static YStream *stream_get(Mux *m, uint32_t id) {
    int i;
    for (i = 0; i < MAX_STREAMS; i++) {
        if (m->streams[i].used && m->streams[i].id == id) return &m->streams[i];
    }
    return NULL;
}

static void stream_wake_all(Mux *m) {
    int i;
    for (i = 0; i < MAX_STREAMS; i++) {
        if (m->streams[i].ev) SetEvent(m->streams[i].ev);
    }
}

static DWORD WINAPI mux_reader(LPVOID arg) {
    Mux *m = (Mux *)arg;
    for (;;) {
        while (m->plain_len >= 12 && !m->dead) {
            uint8_t *h = (uint8_t *)m->plain;
            uint8_t type = h[1];
            uint16_t flags = (uint16_t)((h[2] << 8) | h[3]);
            uint32_t sid = ((uint32_t)h[4] << 24) | ((uint32_t)h[5] << 16) | ((uint32_t)h[6] << 8) | h[7];
            uint32_t len = ((uint32_t)h[8] << 24) | ((uint32_t)h[9] << 16) | ((uint32_t)h[10] << 8) | h[11];
            int need = 12 + (type == Y_DATA ? (int)len : 0);
            YStream *st;
            if (len > 8 * 1024 * 1024) { m->dead = 1; break; }
            if (m->plain_len < need) break;
            if (type == Y_PING && (flags & Y_SYN)) {
                uint8_t rh[12];
                yhdr(rh, Y_PING, Y_ACK, sid, len);
                mux_send_raw(m, rh, 12);
            } else if (type == Y_GOAWAY) {
                m->dead = 1;
            } else if (type == Y_WND || type == Y_DATA) {
                EnterCriticalSection(&m->mu);
                st = stream_get(m, sid);
                if (st) {
                    if (type == Y_WND) {
                        st->send_win += (int)len;
                        if (st->send_win > 8 * 1024 * 1024) st->send_win = 8 * 1024 * 1024;
                    } else if (len && st->buf) {
                        if (buf_grow(&st->buf, &st->cap, st->len + (int)len) == 0) {
                            memcpy(st->buf + st->len, m->plain + 12, len);
                            st->len += (int)len;
                        }
                    }
                    if (flags & Y_RST) st->reset = 1;
                    if (flags & 4) st->fin = 1;
                    SetEvent(st->ev);
                }
                LeaveCriticalSection(&m->mu);
            }
            memmove(m->plain, m->plain + need, (size_t)(m->plain_len - need));
            m->plain_len -= need;
        }
        if (m->dead) break;
        {
            char tmp[8192];
            int r = recv(m->sock, tmp, sizeof(tmp), 0);
            if (r <= 0) break;
            EnterCriticalSection(&m->io);
            if (buf_grow(&m->enc, &m->enc_cap, m->enc_len + r) != 0) {
                LeaveCriticalSection(&m->io);
                break;
            }
            memcpy(m->enc + m->enc_len, tmp, (size_t)r);
            m->enc_len += r;
            if (tls_decrypt(m) != 0) {
                LeaveCriticalSection(&m->io);
                break;
            }
            LeaveCriticalSection(&m->io);
        }
    }
    m->dead = 1;
    stream_wake_all(m);
    return 0;
}

static int tls_handshake(Mux *m, const char *host) {
    SCHANNEL_CRED sc;
    SECURITY_STATUS ss;
    DWORD flags = ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MANUAL_CRED_VALIDATION |
                  ISC_REQ_CONFIDENTIALITY | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT;
    char ibuf[32768];
    int ibuf_len = 0;
    int have = 0;
    TimeStamp ts;
    memset(&sc, 0, sizeof(sc));
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_SERVERNAME_CHECK;
    ss = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &sc, NULL, NULL, &m->cred, &ts);
    if (ss != SEC_E_OK) return -1;
    m->cred_ok = 1;
    for (;;) {
        SecBuffer outb, inb[2];
        SecBufferDesc outd, ind;
        DWORD attr = 0;
        outb.BufferType = SECBUFFER_TOKEN;
        outb.cbBuffer = 0;
        outb.pvBuffer = NULL;
        outd.ulVersion = SECBUFFER_VERSION;
        outd.cBuffers = 1;
        outd.pBuffers = &outb;
        if (ibuf_len > 0) {
            inb[0].BufferType = SECBUFFER_TOKEN;
            inb[0].pvBuffer = ibuf;
            inb[0].cbBuffer = (unsigned)ibuf_len;
            inb[1].BufferType = SECBUFFER_EMPTY;
            inb[1].pvBuffer = NULL;
            inb[1].cbBuffer = 0;
            ind.ulVersion = SECBUFFER_VERSION;
            ind.cBuffers = 2;
            ind.pBuffers = inb;
        }
        ss = InitializeSecurityContextA(&m->cred, have ? &m->ctx : NULL, (SEC_CHAR *)host, flags,
                                        0, 0, ibuf_len > 0 ? &ind : NULL, 0, &m->ctx, &outd, &attr, &ts);
        have = 1;
        if (outb.cbBuffer && outb.pvBuffer) {
            if (send_all(m->sock, (char *)outb.pvBuffer, (int)outb.cbBuffer) != 0) {
                FreeContextBuffer(outb.pvBuffer);
                return -1;
            }
            FreeContextBuffer(outb.pvBuffer);
        }
        if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) {
            int extra = 0;
            if (ibuf_len > 0 && inb[1].BufferType == SECBUFFER_EXTRA) extra = (int)inb[1].cbBuffer;
            if (extra > 0) memmove(ibuf, ibuf + ibuf_len - extra, (size_t)extra);
            ibuf_len = extra;
        }
        if (ss == SEC_E_OK) {
            m->ctx_ok = 1;
            if (ibuf_len > 0) {
                if (buf_grow(&m->enc, &m->enc_cap, ibuf_len) != 0) return -1;
                memcpy(m->enc, ibuf, (size_t)ibuf_len);
                m->enc_len = ibuf_len;
            }
            if (QueryContextAttributes(&m->ctx, SECPKG_ATTR_STREAM_SIZES, &m->sz) != SEC_E_OK) return -1;
            return 0;
        }
        if (ss == SEC_E_INCOMPLETE_MESSAGE || ss == SEC_I_CONTINUE_NEEDED) {
            int r;
            if (ibuf_len >= (int)sizeof(ibuf)) return -1;
            r = recv(m->sock, ibuf + ibuf_len, (int)sizeof(ibuf) - ibuf_len, 0);
            if (r <= 0) return -1;
            ibuf_len += r;
            continue;
        }
        if (ss == SEC_E_UNTRUSTED_ROOT || ss == SEC_E_CERT_EXPIRED || (unsigned)ss == 0x80090325u) {
            m->ctx_ok = 1;
            if (QueryContextAttributes(&m->ctx, SECPKG_ATTR_STREAM_SIZES, &m->sz) != SEC_E_OK) return -1;
            return 0;
        }
        {
            char eb[64];
            snprintf(eb, sizeof(eb), "tls failed %08lx", (unsigned long)ss);
            set_err(eb);
        }
        return -1;
    }
}

static YStream *mux_open(Mux *m, uint32_t id) {
    YStream *st = NULL;
    int i;
    uint8_t h[12];
    EnterCriticalSection(&m->mu);
    if (id == 0) {
        id = m->next_id;
        m->next_id += 2;
    }
    for (i = 0; i < MAX_STREAMS; i++) {
        if (!m->streams[i].used) { st = &m->streams[i]; break; }
    }
    if (!st) { LeaveCriticalSection(&m->mu); return NULL; }
    if (!st->buf) {
        st->buf = (char *)malloc(8192);
        st->cap = st->buf ? 8192 : 0;
    }
    if (!st->ev) st->ev = CreateEvent(NULL, FALSE, FALSE, NULL);
    st->id = id;
    st->used = 1;
    st->reset = 0;
    st->fin = 0;
    st->len = 0;
    st->send_win = Y_INIT_WIN;
    st->crypt = 0;
    st->enc_ready = 0;
    st->dec_ready = 0;
    st->enc_used = 16;
    st->dec_used = 16;
    LeaveCriticalSection(&m->mu);
    yhdr(h, Y_WND, Y_SYN, id, (uint32_t)(Y_RECV_MAX - Y_INIT_WIN));
    if (mux_send_raw(m, h, 12) != 0) {
        st->used = 0;
        return NULL;
    }
    return st;
}

static int stream_read_some(Mux *m, YStream *st, char *out, int cap) {
    int n;
    uint8_t h[12];
    for (;;) {
        EnterCriticalSection(&m->mu);
        if (st->len > 0) {
            n = st->len < cap ? st->len : cap;
            memcpy(out, st->buf, (size_t)n);
            memmove(st->buf, st->buf + n, (size_t)(st->len - n));
            st->len -= n;
            LeaveCriticalSection(&m->mu);
            break;
        }
        if (m->dead || st->reset || st->fin || !st->used) {
            LeaveCriticalSection(&m->mu);
            return -1;
        }
        LeaveCriticalSection(&m->mu);
        WaitForSingleObject(st->ev, 200);
    }
    yhdr(h, Y_WND, 0, st->id, (uint32_t)n);
    mux_send_raw(m, h, 12);
    return n;
}

static int stream_read(Mux *m, YStream *st, char *out, int n) {
    int off = 0;
    while (off < n) {
        int r = stream_read_some(m, st, out + off, n - off);
        if (r <= 0) return -1;
        off += r;
    }
    return 0;
}

static int stream_write(Mux *m, YStream *st, const char *data, int n) {
    int off = 0;
    while (off < n) {
        int chunk;
        uint8_t h[12];
        EnterCriticalSection(&m->mu);
        while (!m->dead && st->used && st->send_win <= 0) {
            LeaveCriticalSection(&m->mu);
            WaitForSingleObject(st->ev, 200);
            EnterCriticalSection(&m->mu);
        }
        if (m->dead || !st->used) { LeaveCriticalSection(&m->mu); return -1; }
        chunk = n - off;
        if (chunk > st->send_win) chunk = st->send_win;
        if (chunk > 16384) chunk = 16384;
        st->send_win -= chunk;
        LeaveCriticalSection(&m->mu);
        yhdr(h, Y_DATA, 0, st->id, (uint32_t)chunk);
        if (mux_send_raw(m, h, 12) != 0 || mux_send_raw(m, data + off, chunk) != 0) return -1;
        off += chunk;
    }
    return 0;
}

static void stream_release(Mux *m, YStream *st) {
    uint8_t h[12];
    if (!m->dead) {
        yhdr(h, Y_WND, Y_RST, st->id, 0);
        mux_send_raw(m, h, 12);
    }
    EnterCriticalSection(&m->mu);
    st->used = 0;
    st->reset = 1;
    st->len = 0;
    if (st->ev) SetEvent(st->ev);
    LeaveCriticalSection(&m->mu);
}

static int aes_block(Mux *m, const uint8_t in[16], uint8_t out[16]) {
    ULONG n = 0;
    return BCryptEncrypt(m->aes, (PUCHAR)in, 16, NULL, NULL, 0, out, 16, &n, 0) == 0 ? 0 : -1;
}

static void cfb_apply(Mux *m, uint8_t next[16], uint8_t ks[16], int *used,
                      const uint8_t *in, uint8_t *out, int n, int decrypt) {
    int off = 0;
    while (off < n) {
        int room, take, i;
        if (*used == 16) {
            aes_block(m, next, ks);
            *used = 0;
        }
        room = 16 - *used;
        take = n - off;
        if (take > room) take = room;
        for (i = 0; i < take; i++) {
            uint8_t ct = decrypt ? in[off + i] : (uint8_t)(in[off + i] ^ ks[*used + i]);
            out[off + i] = decrypt ? (uint8_t)(in[off + i] ^ ks[*used + i]) : ct;
            next[*used + i] = ct;
        }
        *used += take;
        off += take;
    }
}

static int mux_init_aes(Mux *m) {
    BCRYPT_ALG_HANDLE hmac = NULL;
    uint8_t dk[16];
    WCHAR mode[] = L"ChainingModeECB";
    NTSTATUS st;
    st = BCryptOpenAlgorithmProvider(&hmac, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st != 0) return -1;
    st = BCryptDeriveKeyPBKDF2(hmac, (PUCHAR)g.token, (ULONG)strlen(g.token),
                               (PUCHAR)"frp", 3, 64, dk, 16, 0);
    BCryptCloseAlgorithmProvider(hmac, 0);
    if (st != 0) return -1;
    st = BCryptOpenAlgorithmProvider(&m->aes_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st != 0) return -1;
    st = BCryptSetProperty(m->aes_alg, BCRYPT_CHAINING_MODE, (PUCHAR)mode, sizeof(mode), 0);
    if (st != 0) return -1;
    st = BCryptGenerateSymmetricKey(m->aes_alg, &m->aes, NULL, 0, dk, 16, 0);
    return st == 0 ? 0 : -1;
}

static int stream_write_app(Mux *m, YStream *st, const char *data, int n) {
    uint8_t iv[16];
    char *ct;
    int rc;
    if (!st->crypt) return stream_write(m, st, data, n);
    if (!st->enc_ready) {
        if (BCryptGenRandom(NULL, iv, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return -1;
        memcpy(st->enc_next, iv, 16);
        st->enc_used = 16;
        st->enc_ready = 1;
        if (stream_write(m, st, (char *)iv, 16) != 0) return -1;
    }
    ct = (char *)malloc((size_t)n);
    if (!ct) return -1;
    cfb_apply(m, st->enc_next, st->enc_ks, &st->enc_used, (const uint8_t *)data, (uint8_t *)ct, n, 0);
    rc = stream_write(m, st, ct, n);
    free(ct);
    return rc;
}

static int stream_read_app(Mux *m, YStream *st, char *out, int n) {
    char iv[16];
    char *ct;
    if (!st->crypt) return stream_read(m, st, out, n);
    if (!st->dec_ready) {
        if (stream_read(m, st, iv, 16) != 0) return -1;
        memcpy(st->dec_next, iv, 16);
        st->dec_used = 16;
        st->dec_ready = 1;
    }
    ct = (char *)malloc((size_t)n);
    if (!ct) return -1;
    if (stream_read(m, st, ct, n) != 0) { free(ct); return -1; }
    cfb_apply(m, st->dec_next, st->dec_ks, &st->dec_used, (const uint8_t *)ct, (uint8_t *)out, n, 1);
    free(ct);
    return 0;
}

static int write_msg(Mux *m, YStream *st, unsigned char type, const char *json) {
    int n = (int)strlen(json);
    unsigned char hdr[9];
    hdr[0] = type;
    memset(hdr + 1, 0, 8);
    hdr[5] = (unsigned char)((n >> 24) & 0xff);
    hdr[6] = (unsigned char)((n >> 16) & 0xff);
    hdr[7] = (unsigned char)((n >> 8) & 0xff);
    hdr[8] = (unsigned char)(n & 0xff);
    if (stream_write_app(m, st, (char *)hdr, 9) != 0) return -1;
    return stream_write_app(m, st, json, n);
}

static int read_msg(Mux *m, YStream *st, unsigned char *type, char **body) {
    unsigned char hdr[9];
    uint32_t hi, lo;
    int n;
    *body = NULL;
    if (stream_read_app(m, st, (char *)hdr, 9) != 0) return -1;
    *type = hdr[0];
    hi = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 8) | hdr[4];
    lo = ((uint32_t)hdr[5] << 24) | ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 8) | hdr[8];
    if (hi != 0 || lo > 1024 * 1024) return -1;
    n = (int)lo;
    *body = (char *)malloc((size_t)n + 1);
    if (!*body) return -1;
    if (n && stream_read_app(m, st, *body, n) != 0) { free(*body); *body = NULL; return -1; }
    (*body)[n] = 0;
    return 0;
}

typedef struct { Mux *m; YStream *st; char local_host[128]; int local_port; } WorkArg;

typedef struct {
    Mux *m;
    YStream *st;
    SOCKET loc;
} CopyArg;

#define UDP_SESS_MAX 64

typedef struct {
    int used;
    char key[64];
    char r_json[256];
    SOCKET sock;
    HANDLE th;
    volatile LONG dead;
    Mux *m;
    YStream *st;
    CRITICAL_SECTION *wmu;
} UdpSess;

static int json_get_obj(const char *body, const char *key, char *dst, size_t cap) {
    char pat[64];
    const char *p, *start;
    int depth;
    if (!body || !key || !dst || !cap) return -1;
    dst[0] = 0;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(body, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':') p++;
    if (*p != '{') return -1;
    start = p;
    depth = 0;
    do {
        if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
        else if (!*p) return -1;
        p++;
    } while (depth > 0);
    if ((size_t)(p - start) >= cap) return -1;
    memcpy(dst, start, (size_t)(p - start));
    dst[p - start] = 0;
    return 0;
}

static DWORD WINAPI stream_to_sock(LPVOID p) {
    CopyArg *c = (CopyArg *)p;
    char buf[8192];
    for (;;) {
        int n = stream_read_some(c->m, c->st, buf, (int)sizeof(buf));
        if (n <= 0) break;
        if (send_all(c->loc, buf, n) != 0) break;
    }
    shutdown(c->loc, SD_SEND);
    return 0;
}

static DWORD WINAPI udp_sess_reader(LPVOID p) {
    UdpSess *s = (UdpSess *)p;
    char buf[8192];
    char b64[11000];
    char json[12000];
    for (;;) {
        DWORD ms = 30000;
        int n;
        if (InterlockedCompareExchange(&s->dead, 0, 0)) break;
        setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms));
        n = recvfrom(s->sock, buf, (int)sizeof(buf), 0, NULL, NULL);
        if (n <= 0) break;
        if (InterlockedCompareExchange(&s->dead, 0, 0)) break;
        b64_encode((const unsigned char *)buf, n, b64, (int)sizeof(b64));
        snprintf(json, sizeof(json), "{\"c\":\"%s\",\"r\":%s}", b64, s->r_json);
        EnterCriticalSection(s->wmu);
        if (write_msg(s->m, s->st, TYPE_UDP_PACKET, json) != 0) {
            LeaveCriticalSection(s->wmu);
            break;
        }
        LeaveCriticalSection(s->wmu);
    }
    return 0;
}

static void udp_sess_cleanup(UdpSess *sess, int n) {
    int i;
    for (i = 0; i < n; i++) {
        if (!sess[i].used) continue;
        InterlockedExchange(&sess[i].dead, 1);
        if (sess[i].sock != INVALID_SOCKET) {
            closesocket(sess[i].sock);
            sess[i].sock = INVALID_SOCKET;
        }
        if (sess[i].th) {
            WaitForSingleObject(sess[i].th, 5000);
            CloseHandle(sess[i].th);
            sess[i].th = NULL;
        }
        sess[i].used = 0;
    }
}

static DWORD WINAPI work_thread(LPVOID p) {
    WorkArg *w = (WorkArg *)p;
    Mux *m = w->m;
    YStream *st = w->st;
    SOCKET loc = INVALID_SOCKET;
    unsigned char type;
    char *body = NULL;
    char key[33], json[512], err[128];
    int64_t ts = (int64_t)time(NULL);
    CopyArg *ca;
    HANDLE th;
    auth_key(g.token, ts, key);
    snprintf(json, sizeof(json),
             "{\"run_id\":\"%s\",\"privilege_key\":\"%s\",\"timestamp\":%lld}",
             g.run_id, key, (long long)ts);
    if (write_msg(m, st, TYPE_NEW_WORK, json) != 0 || read_msg(m, st, &type, &body) != 0 || type != TYPE_START_WORK) {
        free(body);
        stream_release(m, st);
        free(w);
        InterlockedDecrement(&m->refs);
        return 0;
    }
    json_get(body, "error", err, sizeof(err));
    free(body);
    body = NULL;
    if (err[0]) {
        stream_release(m, st);
        free(w);
        InterlockedDecrement(&m->refs);
        return 0;
    }

    if (strcmp(g.proxy_type, "udp") == 0) {
        UdpSess sess[UDP_SESS_MAX];
        CRITICAL_SECTION wmu;
        struct sockaddr_in local_addr;
        int i;
        memset(sess, 0, sizeof(sess));
        for (i = 0; i < UDP_SESS_MAX; i++) sess[i].sock = INVALID_SOCKET;
        InitializeCriticalSection(&wmu);
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = htons((u_short)w->local_port);
        if (inet_pton(AF_INET, w->local_host[0] ? w->local_host : "127.0.0.1", &local_addr.sin_addr) != 1)
            inet_pton(AF_INET, "127.0.0.1", &local_addr.sin_addr);
        for (;;) {
            char c_b64[11000], r_obj[256], ip[64], sk[64];
            unsigned char payload[8192];
            int plen, port, si, found;
            UdpSess *s;
            if (read_msg(m, st, &type, &body) != 0) break;
            if (type == TYPE_PING) {
                ts = (int64_t)time(NULL);
                auth_key(g.token, ts, key);
                snprintf(json, sizeof(json), "{\"privilege_key\":\"%s\",\"timestamp\":%lld}",
                         key, (long long)ts);
                EnterCriticalSection(&wmu);
                if (write_msg(m, st, TYPE_PONG, json) != 0) {
                    LeaveCriticalSection(&wmu);
                    free(body); body = NULL;
                    break;
                }
                LeaveCriticalSection(&wmu);
            } else if (type == TYPE_UDP_PACKET) {
                c_b64[0] = 0; r_obj[0] = 0; ip[0] = 0;
                json_get(body, "c", c_b64, sizeof(c_b64));
                if (json_get_obj(body, "r", r_obj, sizeof(r_obj)) != 0) {
                    free(body); body = NULL;
                    continue;
                }
                json_get(r_obj, "IP", ip, sizeof(ip));
                port = json_get_int(r_obj, "Port", 0);
                if (!ip[0] || port <= 0) {
                    free(body); body = NULL;
                    continue;
                }
                plen = b64_decode(c_b64, payload, (int)sizeof(payload));
                if (plen < 0) {
                    free(body); body = NULL;
                    continue;
                }
                snprintf(sk, sizeof(sk), "%s:%d", ip, port);
                found = -1;
                for (si = 0; si < UDP_SESS_MAX; si++) {
                    if (sess[si].used && strcmp(sess[si].key, sk) == 0) { found = si; break; }
                }
                if (found < 0) {
                    for (si = 0; si < UDP_SESS_MAX; si++) {
                        if (!sess[si].used) { found = si; break; }
                    }
                    if (found < 0) {
                        free(body); body = NULL;
                        continue;
                    }
                    s = &sess[found];
                    memset(s, 0, sizeof(*s));
                    s->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    if (s->sock == INVALID_SOCKET) {
                        free(body); body = NULL;
                        continue;
                    }
                    snprintf(s->key, sizeof(s->key), "%s", sk);
                    snprintf(s->r_json, sizeof(s->r_json), "%s", r_obj);
                    s->m = m; s->st = st; s->wmu = &wmu; s->used = 1;
                    s->th = CreateThread(NULL, 0, udp_sess_reader, s, 0, NULL);
                    if (!s->th) {
                        closesocket(s->sock);
                        s->sock = INVALID_SOCKET;
                        s->used = 0;
                        free(body); body = NULL;
                        continue;
                    }
                } else {
                    s = &sess[found];
                    snprintf(s->r_json, sizeof(s->r_json), "%s", r_obj);
                }
                if (plen > 0)
                    sendto(s->sock, (const char *)payload, plen, 0,
                           (struct sockaddr *)&local_addr, (int)sizeof(local_addr));
            }
            free(body);
            body = NULL;
        }
        free(body);
        udp_sess_cleanup(sess, UDP_SESS_MAX);
        DeleteCriticalSection(&wmu);
        stream_release(m, st);
        free(w);
        InterlockedDecrement(&m->refs);
        return 0;
    }

    loc = tcp_connect(w->local_host, w->local_port);
    if (loc == INVALID_SOCKET) {
        stream_release(m, st);
        free(w);
        InterlockedDecrement(&m->refs);
        return 0;
    }
    ca = (CopyArg *)malloc(sizeof(*ca));
    if (!ca) { closesocket(loc); stream_release(m, st); free(w); InterlockedDecrement(&m->refs); return 0; }
    ca->m = m; ca->st = st; ca->loc = loc;
    th = CreateThread(NULL, 0, stream_to_sock, ca, 0, NULL);
    {
        char buf[8192];
        for (;;) {
            int n = recv(loc, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (stream_write(m, st, buf, n) != 0) break;
        }
    }
    shutdown(loc, SD_RECEIVE);
    if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
    free(ca);
    closesocket(loc);
    stream_release(m, st);
    free(w);
    InterlockedDecrement(&m->refs);
    return 0;
}

static void mux_close(Mux *m) {
    int i;
    if (!m) return;
    m->dead = 1;
    if (m->sock != INVALID_SOCKET) {
        shutdown(m->sock, SD_BOTH);
        closesocket(m->sock);
        m->sock = INVALID_SOCKET;
    }
    stream_wake_all(m);
    if (m->reader) {
        WaitForSingleObject(m->reader, 5000);
        CloseHandle(m->reader);
    }
    while (m->refs > 0) Sleep(20);
    if (m->ctx_ok) DeleteSecurityContext(&m->ctx);
    if (m->cred_ok) FreeCredentialsHandle(&m->cred);
    if (m->aes) BCryptDestroyKey(m->aes);
    if (m->aes_alg) BCryptCloseAlgorithmProvider(m->aes_alg, 0);
    DeleteCriticalSection(&m->io);
    DeleteCriticalSection(&m->mu);
    free(m->enc);
    free(m->plain);
    for (i = 0; i < MAX_STREAMS; i++) {
        free(m->streams[i].buf);
        if (m->streams[i].ev) CloseHandle(m->streams[i].ev);
    }
    free(m);
}

static Mux *mux_connect(void) {
    Mux *m = (Mux *)calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->sock = INVALID_SOCKET;
    m->next_id = 3;
    InitializeCriticalSection(&m->io);
    InitializeCriticalSection(&m->mu);
    m->sock = tcp_connect(g.server_addr, g.server_port);
    if (m->sock == INVALID_SOCKET) { mux_close(m); set_err("connect frps failed"); return NULL; }
    if (tls_handshake(m, g.server_addr) != 0) { mux_close(m); set_err("tls failed"); return NULL; }
    m->reader = CreateThread(NULL, 0, mux_reader, m, 0, NULL);
    if (!m->reader) { mux_close(m); return NULL; }
    return m;
}

static int frp_session(void) {
    Mux *m;
    YStream *ctl;
    unsigned char type = 0;
    char *body = NULL;
    char key[33], json[1024], err[256], run_id[64], remote[128];
    int64_t ts = (int64_t)time(NULL);
    m = mux_connect();
    if (!m) return -1;
    ctl = mux_open(m, 1);
    if (!ctl) { mux_close(m); set_err("yamux open failed"); return -1; }
    auth_key(g.token, ts, key);
    snprintf(json, sizeof(json),
             "{\"version\":\"0.71.0\",\"hostname\":\"eadk\",\"os\":\"windows\",\"arch\":\"amd64\","
             "\"privilege_key\":\"%s\",\"timestamp\":%lld,\"pool_count\":0}",
             key, (long long)ts);
    if (write_msg(m, ctl, TYPE_LOGIN, json) != 0 || read_msg(m, ctl, &type, &body) != 0 || type != TYPE_LOGIN_RESP) {
        free(body); mux_close(m); set_err("login failed"); return -1;
    }
    err[0] = 0; run_id[0] = 0;
    json_get(body, "error", err, sizeof(err));
    json_get(body, "run_id", run_id, sizeof(run_id));
    free(body); body = NULL;
    if (err[0] || !run_id[0]) { mux_close(m); set_err(err[0] ? err : "login failed"); return -1; }
    if (mux_init_aes(m) != 0) { mux_close(m); set_err("aes init failed"); return -1; }
    ctl->crypt = 1;
    EnterCriticalSection(&g.mu);
    snprintf(g.run_id, sizeof(g.run_id), "%s", run_id);
    LeaveCriticalSection(&g.mu);
    {
        int chosen = 0, attempt;
        PortSet banned;
        banned.n = 0;
        if (dashboard_pick_port(&chosen) != 0) {
            mux_close(m);
            set_err(g.pick_reason[0] ? g.pick_reason : "no free remote port");
            return -1;
        }
        for (attempt = 0; attempt < 8; attempt++) {
            while (port_set_has(&banned, chosen)) {
                PortSet online, offline;
                online.n = offline.n = 0;
                /* re-query dashboard and treat banned as online */
                {
                    char host[128], *body2 = NULL;
                    snprintf(host, sizeof(host), "%s",
                             g.dashboard_addr[0] ? g.dashboard_addr : g.server_addr);
                    if (g.dashboard_port > 0 &&
                        http_get_text(host, g.dashboard_port, proxy_api_path(),
                                      g.dashboard_user, g.dashboard_password, &body2, NULL) == 0) {
                        parse_proxy_tcp(body2, &online, &offline);
                        free(body2);
                    }
                }
                {
                    int i;
                    for (i = 0; i < banned.n; i++) port_set_add(&online, banned.v[i]);
                }
                if (pick_remote_port(&online, &offline, &chosen, g.pick_reason, sizeof(g.pick_reason)) != 0) {
                    mux_close(m);
                    set_err(g.pick_reason);
                    return -1;
                }
            }
            g.remote_port = chosen;
            snprintf(json, sizeof(json),
                     "{\"proxy_name\":\"%s\",\"proxy_type\":\"%s\",\"remote_port\":%d}",
                     g.proxy_name, g.proxy_type, g.remote_port);
            free(body); body = NULL;
            if (write_msg(m, ctl, TYPE_NEW_PROXY, json) != 0 ||
                read_msg(m, ctl, &type, &body) != 0 || type != TYPE_NEW_PROXY_RESP) {
                free(body); mux_close(m); set_err("new proxy failed"); return -1;
            }
            err[0] = 0; remote[0] = 0;
            json_get(body, "error", err, sizeof(err));
            json_get(body, "remote_addr", remote, sizeof(remote));
            if (!err[0]) break;
            /* port conflict -> ban and retry */
            if (strstr(err, "port") || strstr(err, "Port") || strstr(err, "occupy") ||
                strstr(err, "already") || strstr(err, "bind")) {
                port_set_add(&banned, chosen);
                free(body); body = NULL;
                /* force re-pick on next loop via banned */
                {
                    PortSet online, offline;
                    char host[128], *body2 = NULL;
                    online.n = offline.n = 0;
                    snprintf(host, sizeof(host), "%s",
                             g.dashboard_addr[0] ? g.dashboard_addr : g.server_addr);
                    if (g.dashboard_port > 0 &&
                        http_get_text(host, g.dashboard_port, proxy_api_path(),
                                      g.dashboard_user, g.dashboard_password, &body2, NULL) == 0) {
                        parse_proxy_tcp(body2, &online, &offline);
                        free(body2);
                    }
                    {
                        int i;
                        for (i = 0; i < banned.n; i++) port_set_add(&online, banned.v[i]);
                    }
                    if (pick_remote_port(&online, &offline, &chosen, g.pick_reason, sizeof(g.pick_reason)) != 0) {
                        mux_close(m);
                        set_err(g.pick_reason);
                        return -1;
                    }
                }
                continue;
            }
            free(body); mux_close(m); set_err(err); return -1;
        }
        free(body); body = NULL;
        if (err[0] || !remote[0]) {
            mux_close(m);
            set_err(err[0] ? err : "new proxy failed");
            return -1;
        }
    }
    EnterCriticalSection(&g.mu);
    snprintf(g.remote_addr, sizeof(g.remote_addr), "%s", remote);
    g.last_remote_port = g.remote_port;
    g.frp_ok = 1;
    g.last_error[0] = 0;
    LeaveCriticalSection(&g.mu);
    write_status_file();
    for (;;) {
        if (InterlockedCompareExchange(&g.stop_flag, 0, 0)) break;
        if (InterlockedCompareExchange(&g.reconnect, 0, 0)) break;
        if (read_msg(m, ctl, &type, &body) != 0) break;
        if (type == TYPE_REQ_WORK) {
            YStream *ws = mux_open(m, 0);
            WorkArg *w;
            if (ws) {
                w = (WorkArg *)calloc(1, sizeof(*w));
                if (w) {
                    w->m = m;
                    w->st = ws;
                    snprintf(w->local_host, sizeof(w->local_host), "%s", g.local_host);
                    w->local_port = g.local_port;
                    InterlockedIncrement(&m->refs);
                    if (!CreateThread(NULL, 0, work_thread, w, 0, NULL)) {
                        InterlockedDecrement(&m->refs);
                        stream_release(m, ws);
                        free(w);
                    }
                } else stream_release(m, ws);
            }
        } else if (type == TYPE_PING) {
            ts = (int64_t)time(NULL);
            auth_key(g.token, ts, key);
            snprintf(json, sizeof(json), "{\"privilege_key\":\"%s\",\"timestamp\":%lld}", key, (long long)ts);
            if (write_msg(m, ctl, TYPE_PONG, json) != 0) { free(body); break; }
        }
        free(body);
        body = NULL;
    }
    free(body);
    g.frp_ok = 0;
    mux_close(m);
    set_err("frps disconnected");
    return -1;
}

static DWORD WINAPI frp_thread(LPVOID unused) {
    (void)unused;
    for (;;) {
        if (InterlockedCompareExchange(&g.stop_flag, 0, 0)) break;
        InterlockedExchange(&g.reconnect, 0);
        frp_session();
        write_status_file();
        if (InterlockedCompareExchange(&g.stop_flag, 0, 0)) break;
        Sleep(3000);
    }
    return 0;
}

static void http_reply(SOCKET c, int code, const char *ctype, const char *body) {
    char hdr[256];
    const char *status = code == 404 ? "404 Not Found" : (code == 400 ? "400 Bad Request" : "200 OK");
    int blen = body ? (int)strlen(body) : 0;
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
                     status, ctype, blen);
    if (n > 0) send_all(c, hdr, n);
    if (blen > 0) send_all(c, body, blen);
}

static void handle_http(SOCKET c) {
    char req[16384], path[256], loc[256];
    static char body[24576];
    int n = 0, got;
    const char *bp = g.base_path[0] ? g.base_path : "/tunnel";
    char *sp, *q;
    {
        DWORD ms = 3000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, sizeof(ms));
    }
    for (;;) {
        got = recv(c, req + n, (int)sizeof(req) - 1 - n, 0);
        if (got <= 0) break;
        n += got;
        req[n] = 0;
        if (strstr(req, "\r\n\r\n")) {
            const char *cl = strstr(req, "Content-Length:");
            if (!cl) cl = strstr(req, "content-length:");
            if (cl) {
                int need = atoi(cl + 15);
                const char *b = strstr(req, "\r\n\r\n");
                int have = n - (int)(b + 4 - req);
                if (have >= need) break;
            } else break;
        }
        if (n >= (int)sizeof(req) - 1) break;
    }
    if (n <= 0) return;
    req[n] = 0;
    sp = strchr(req, ' ');
    if (!sp) return;
    sp++;
    q = strchr(sp, ' ');
    if (!q) return;
    if ((size_t)(q - sp) >= sizeof(path)) return;
    memcpy(path, sp, (size_t)(q - sp));
    path[q - sp] = 0;
    q = strchr(path, '?');
    if (q) *q = 0;
    if (strcmp(path, "/") == 0) {
        snprintf(loc, sizeof(loc), "HTTP/1.1 302 Found\r\nLocation: %s/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", bp);
        send_all(c, loc, (int)strlen(loc));
        return;
    }
    if (strncmp(path, bp, strlen(bp)) != 0) {
        snprintf(body, sizeof(body), "{\"error\":\"use path prefix %s/\"}", bp);
        http_reply(c, 404, "application/json", body);
        return;
    }
    sp = path + strlen(bp);
    if (sp[0] == 0) {
        snprintf(loc, sizeof(loc), "HTTP/1.1 302 Found\r\nLocation: %s/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", bp);
        send_all(c, loc, (int)strlen(loc));
        return;
    }
    if (strcmp(sp, "/health") == 0) {
        EnterCriticalSection(&g.mu);
        snprintf(body, sizeof(body),
                 "{\"ok\":true,\"tool\":\"tunnel\",\"product\":\"EADK Tunnel\",\"version\":\"1.0.0\","
                 "\"frp_ok\":%s,\"remote_addr\":\"%s\",\"remote_port\":%d,\"local\":\"%s:%d\","
                 "\"pick\":\"%s\",\"error\":\"%s\"}",
                 g.frp_ok ? "true" : "false", g.remote_addr, g.remote_port,
                 g.local_host, g.local_port, g.pick_reason, g.last_error);
        LeaveCriticalSection(&g.mu);
        http_reply(c, 200, "application/json", body);
    } else if (strcmp(sp, "/api/help") == 0) {
        snprintf(body, sizeof(body),
                 "{\"tool\":\"tunnel\",\"product\":\"EADK Tunnel\",\"version\":\"1.0.0\",\"http_port\":%d,"
                 "\"operations\":["
                 "{\"id\":\"health\",\"method\":\"GET\",\"path\":\"%s/health\",\"side_effect\":false,\"summary\":\"Liveness\"},"
                 "{\"id\":\"help.agent\",\"method\":\"GET\",\"path\":\"%s/help\",\"side_effect\":false,\"summary\":\"Agent manual\"},"
                 "{\"id\":\"help.api\",\"method\":\"GET\",\"path\":\"%s/api/help\",\"side_effect\":false,\"summary\":\"Operations\"},"
                 "{\"id\":\"config.get\",\"method\":\"GET\",\"path\":\"%s/api/config\",\"side_effect\":false,\"summary\":\"Read tunnel config\"},"
                 "{\"id\":\"config.set\",\"method\":\"POST\",\"path\":\"%s/api/config\",\"side_effect\":true,\"summary\":\"Save config and reconnect\"},"
                 "{\"id\":\"ports\",\"method\":\"GET\",\"path\":\"%s/api/ports\",\"side_effect\":false,\"summary\":\"Dashboard online/offline ports\"}"
                 "]}",
                 g.http_port, bp, bp, bp, bp, bp, bp);
        http_reply(c, 200, "application/json", body);
    } else if (strcmp(sp, "/api/config") == 0) {
        if (strncmp(req, "POST", 4) == 0) {
            const char *pb = strstr(req, "\r\n\r\n");
            if (pb) {
                pb += 4;
                json_get(pb, "server_addr", g.server_addr, sizeof(g.server_addr));
                json_get(pb, "token", g.token, sizeof(g.token));
                json_get(pb, "dashboard_addr", g.dashboard_addr, sizeof(g.dashboard_addr));
                json_get(pb, "dashboard_user", g.dashboard_user, sizeof(g.dashboard_user));
                json_get(pb, "dashboard_password", g.dashboard_password, sizeof(g.dashboard_password));
                json_get(pb, "local_host", g.local_host, sizeof(g.local_host));
                json_get(pb, "proxy_name", g.proxy_name, sizeof(g.proxy_name));
                if (strstr(pb, "\"server_port\"")) g.server_port = json_get_int(pb, "server_port", g.server_port);
                if (strstr(pb, "\"dashboard_port\"")) g.dashboard_port = json_get_int(pb, "dashboard_port", g.dashboard_port);
                if (strstr(pb, "\"local_port\"")) g.local_port = json_get_int(pb, "local_port", g.local_port);
                if (strstr(pb, "\"remote_port_min\"")) g.remote_port_min = json_get_int(pb, "remote_port_min", g.remote_port_min);
                if (strstr(pb, "\"remote_port_max\"")) g.remote_port_max = json_get_int(pb, "remote_port_max", g.remote_port_max);
                save_cfg_file();
                InterlockedExchange(&g.reconnect, 1);
                http_reply(c, 200, "application/json", "{\"ok\":true,\"reconnect\":true}");
            } else {
                http_reply(c, 400, "application/json", "{\"ok\":false,\"error\":\"empty body\"}");
            }
        } else {
            EnterCriticalSection(&g.mu);
            snprintf(body, sizeof(body),
                     "{\"ok\":true,\"server_addr\":\"%s\",\"server_port\":%d,\"token\":\"%s\","
                     "\"dashboard_addr\":\"%s\",\"dashboard_port\":%d,\"dashboard_user\":\"%s\","
                     "\"dashboard_password\":\"%s\",\"local_host\":\"%s\",\"local_port\":%d,"
                     "\"remote_port\":%d,\"last_remote_port\":%d,"
                     "\"remote_port_min\":%d,\"remote_port_max\":%d,\"proxy_name\":\"%s\"}",
                     g.server_addr, g.server_port, g.token,
                     g.dashboard_addr, g.dashboard_port, g.dashboard_user, g.dashboard_password,
                     g.local_host, g.local_port, g.remote_port, g.last_remote_port,
                     g.remote_port_min, g.remote_port_max, g.proxy_name);
            LeaveCriticalSection(&g.mu);
            http_reply(c, 200, "application/json", body);
        }
    } else if (strcmp(sp, "/api/ports") == 0) {
        char host[128], *dash = NULL;
        PortSet online, offline;
        int i, pos = 0, chosen = 0;
        online.n = offline.n = 0;
        snprintf(host, sizeof(host), "%s", g.dashboard_addr[0] ? g.dashboard_addr : g.server_addr);
        if (g.dashboard_port > 0 &&
            http_get_text(host, g.dashboard_port, proxy_api_path(),
                          g.dashboard_user, g.dashboard_password, &dash, NULL) == 0) {
            parse_proxy_tcp(dash, &online, &offline);
            free(dash);
        }
        pick_remote_port(&online, &offline, &chosen, g.pick_reason, sizeof(g.pick_reason));
        pos += snprintf(body + pos, sizeof(body) - (size_t)pos,
                        "{\"ok\":true,\"dashboard\":\"%s:%d\",\"chosen\":%d,\"pick\":\"%s\",\"online\":[",
                        host, g.dashboard_port, chosen, g.pick_reason);
        for (i = 0; i < online.n && pos < (int)sizeof(body) - 32; i++)
            pos += snprintf(body + pos, sizeof(body) - (size_t)pos, "%s%d", i ? "," : "", online.v[i]);
        pos += snprintf(body + pos, sizeof(body) - (size_t)pos, "],\"offline\":[");
        for (i = 0; i < offline.n && pos < (int)sizeof(body) - 32; i++)
            pos += snprintf(body + pos, sizeof(body) - (size_t)pos, "%s%d", i ? "," : "", offline.v[i]);
        snprintf(body + pos, sizeof(body) - (size_t)pos, "]}");
        http_reply(c, 200, "application/json", body);
    } else if (strcmp(sp, "/help") == 0 || strcmp(sp, "/docs") == 0) {
        EnterCriticalSection(&g.mu);
        snprintf(body, sizeof(body),
                 "# EADK Tunnel — Agent 操作手册\n\n"
                 "- 机器清单: http://127.0.0.1:18081%s/api/help\n"
                 "- WebUI: http://127.0.0.1:18081%s/\n"
                 "- Agent 接口: http://127.0.0.1:18081%s/help\n\n"
                 "## 1. 约定\n\n"
                 "只把本机 Gateway TCP 映到 frps（瑞芯微无关）。token / 仪表盘账号按服务器是否开启选填，默认空。\n"
                 "外网端口按仪表盘占用自动选择，见 DESIGN.md。\n"
                 "公网入口没有额外鉴权，等于把套件控制台暴露出去。\n\n"
                 "## 2. 状态\n\n"
                 "- frp_ok: %s\n"
                 "- remote_addr: %s\n"
                 "- remote_port: %d\n"
                 "- pick: %s\n"
                 "- local: %s:%d\n"
                 "- error: %s\n\n"
                 "## 3. 查看\n\n"
                 "curl.exe -s http://127.0.0.1:%d%s/health\n\n"
                 "curl.exe -s http://127.0.0.1:%d%s/api/ports\n",
                 bp, bp, bp,
                 g.frp_ok ? "true" : "false", g.remote_addr, g.remote_port, g.pick_reason,
                 g.local_host, g.local_port, g.last_error,
                 g.http_port, bp, g.http_port, bp);
        LeaveCriticalSection(&g.mu);
        http_reply(c, 200, "text/plain; charset=utf-8", body);
    } else if (strcmp(sp, "/") == 0) {
        snprintf(body, sizeof(body),
                 "<!doctype html><html lang=zh-CN><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">"
                 "<title>EADK Tunnel</title>"
                 "<style>"
                 ":root{--ok:#0f766e;--bad:#b42318;--line:#d9e2ec;--bg:#f4f7fa;--card:#fff;--ink:#132033}"
                 "*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,PingFang SC,Microsoft YaHei,sans-serif;background:var(--bg);color:var(--ink)}"
                 ".wrap{max-width:760px;margin:0 auto;padding:20px 14px 40px}"
                 "h1{margin:0 0 6px;font-size:1.45rem}h2{margin:18px 0 8px;font-size:1.05rem}"
                 ".sub{color:#5b6b82;font-size:13px;margin:0 0 14px}"
                 ".card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:0 0 12px}"
                 ".st{display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap}"
                 ".pill{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700}"
                 ".pill.on{background:#ccfbf1;color:var(--ok)}.pill.off{background:#fee4e2;color:var(--bad)}"
                 ".err{margin-top:8px;padding:10px 12px;border-radius:8px;background:#fef2f2;color:#991b1b;font-size:13px;display:none;white-space:pre-wrap}"
                 ".err.show{display:block}.okbox{margin-top:8px;padding:10px 12px;border-radius:8px;background:#ecfdf5;color:#065f46;font-size:13px;display:none}"
                 ".okbox.show{display:block}.okbox a{color:#065f46;font-weight:700}"
                 "label{display:block;margin:10px 0 4px;font-size:12px;font-weight:700;color:#334155}"
                 "input,select{width:100%%;padding:9px 11px;border:1px solid var(--line);border-radius:8px;font:inherit}"
                 ".row{display:grid;grid-template-columns:1fr 1fr;gap:10px}@media(max-width:560px){.row{grid-template-columns:1fr}}"
                 ".hint{font-size:12px;color:#64748b;margin:4px 0 0}"
                 ".actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}"
                 "button{border:0;border-radius:8px;padding:10px 14px;font:inherit;font-weight:700;cursor:pointer}"
                 ".primary{background:#0a6c74;color:#fff}.ghost{background:#e8eef5}"
                 ".msg{margin-top:10px;font-size:13px;color:#0a6c74;min-height:1.2em}"
                 "details{margin-top:8px}summary{cursor:pointer;font-weight:700;font-size:13px}"
                 "</style></head><body><div class=wrap>"
                 "<h1>EADK Tunnel</h1>"
                 "<p class=sub>把本机 Gateway 映到 frps 公网。token / 仪表盘密码：服务器开了再填，否则留空。</p>"
                 "<div class=card><div class=st><span id=pill class=\"pill off\">检测中</span>"
                 "<div><div id=sum>—</div><div class=hint id=pick></div></div></div>"
                 "<div id=err class=err></div><div id=okbox class=okbox></div></div>"
                 "<div class=card><h2 style=\"margin-top:0\">1. frps 连接</h2>"
                 "<div class=row><div><label>服务器地址</label><input id=sa placeholder=39.97.234.200></div>"
                 "<div><label>登录端口 bindPort</label><input id=sp type=number placeholder=7321></div></div>"
                 "<label>auth.token（服务器开了 token 才填）</label><input id=tk autocomplete=off>"
                 "<p class=hint>与 frps.toml 里 auth.token 一致。当前报 token 不匹配时，多半是这里空了或填错。</p>"
                 "<div class=row><div><label>本机 Gateway 地址</label><input id=lh></div>"
                 "<div><label>本机 Gateway 端口</label><input id=lp type=number></div></div>"
                 "</div>"
                 "<div class=card><h2 style=\"margin-top:0\">2. 仪表盘（选端口用，可选）</h2>"
                 "<label><input id=duse type=checkbox style=\"width:auto;margin-right:6px\">启用仪表盘查询空闲端口</label>"
                 "<div id=dbox style=\"display:none\">"
                 "<div class=row><div><label>仪表盘地址（空=同服务器）</label><input id=da></div>"
                 "<div><label>仪表盘端口</label><input id=dp type=number placeholder=7322></div></div>"
                 "<div class=row><div><label>用户名</label><input id=du></div>"
                 "<div><label>密码</label><input id=dw autocomplete=off></div></div>"
                 "<p class=hint>对应 frps webServer.*。不启用则用上次端口 / 本机端口。</p></div>"
                 "</div>"
                 "<div class=actions>"
                 "<button class=primary onclick=\"save()\">保存并重连</button>"
                 "<button class=ghost onclick=\"refresh()\">刷新状态</button>"
                 "<button class=ghost onclick=\"ports()\">看端口占用</button>"
                 "<a class=ghost style=\"padding:10px 14px;text-decoration:none;display:inline-block\" href=\"help\">Agent 手册</a>"
                 "</div><div class=msg id=msg></div>"
                 "<details class=card><summary>高级</summary>"
                 "<div class=row><div><label>proxy_name</label><input id=pn></div>"
                 "<div><label>端口范围 min-max</label><div class=row><input id=pmin type=number><input id=pmax type=number></div></div></div>"
                 "</details>"
                 "<script>"
                 "const BP='%s';"
                 "const $=id=>document.getElementById(id);"
                 "duse.onchange=()=>{dbox.style.display=duse.checked?'block':'none'};"
                 "async function j(u,opt){const r=await fetch(BP+u,opt);const t=await r.text();try{return JSON.parse(t)}catch(e){return{raw:t}}} "
                 "async function load(){const c=await j('/api/config');sa.value=c.server_addr||'';sp.value=c.server_port||7321;"
                 "tk.value=c.token||'';lh.value=c.local_host||'127.0.0.1';lp.value=c.local_port||18081;"
                 "da.value=c.dashboard_addr||'';dp.value=c.dashboard_port||7322;du.value=c.dashboard_user||'';"
                 "dw.value=c.dashboard_password||'';pn.value=c.proxy_name||'eadk-gateway';"
                 "pmin.value=c.remote_port_min||18000;pmax.value=c.remote_port_max||18999;"
                 "duse.checked=!!(c.dashboard_port>0);duse.onchange();refresh()}"
                 "async function refresh(){const h=await j('/health');const on=!!h.frp_ok;pill.className='pill '+(on?'on':'off');"
                 "pill.textContent=on?'已连接':'未连接';"
                 "sum.textContent=on?('公网 '+h.remote_addr+' · 本机 '+h.local):('本机 '+h.local+' · 等待连接');"
                 "pick.textContent=h.pick?('选端口: '+h.pick):'';"
                 "err.className='err'+(h.error?' show':'');err.textContent=h.error||'';"
                 "okbox.className='okbox'+(on?' show':'');"
                 "if(on){const host=(sa.value||'server');const p=h.remote_port||'';"
                 "okbox.innerHTML='外网打开 Gateway：<a target=_blank href=\"http://'+host+':'+p+'/\">http://'+host+':'+p+'/</a>';}}"
                 "async function save(){msg.textContent='保存中…';"
                 "const o={server_addr:sa.value.trim(),server_port:+sp.value,token:tk.value,"
                 "local_host:lh.value.trim(),local_port:+lp.value,proxy_name:pn.value.trim(),"
                 "dashboard_addr:da.value.trim(),dashboard_port:duse.checked?(+dp.value||7322):0,"
                 "dashboard_user:du.value,dashboard_password:dw.value,"
                 "remote_port_min:+pmin.value||18000,remote_port_max:+pmax.value||18999};"
                 "const r=await j('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)});"
                 "msg.textContent=r.ok?'已保存，正在重连…':(r.error||r.raw||'失败');"
                 "setTimeout(refresh,2500);setTimeout(refresh,5000)}"
                 "async function ports(){const p=await j('/api/ports');msg.textContent=JSON.stringify(p)}"
                 "load();setInterval(refresh,4000);"
                 "</script></div></body></html>",
                 bp);
        http_reply(c, 200, "text/html; charset=utf-8", body);
    } else {
        http_reply(c, 404, "application/json", "{\"error\":\"not found\"}");
    }
}

static int gateway_is_ours(const char *host, int port) {
    SOCKET s;
    char req[128], buf[512];
    int n, total = 0;
    s = tcp_connect(host, port);
    if (s == INVALID_SOCKET) return 0;
    {
        DWORD ms = 800;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, sizeof(ms));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&ms, sizeof(ms));
    }
    snprintf(req, sizeof(req),
             "GET /eadk/health HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    if (send_all(s, req, (int)strlen(req)) != 0) { closesocket(s); return 0; }
    while (total < (int)sizeof(buf) - 1) {
        n = recv(s, buf + total, (int)sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    closesocket(s);
    buf[total] = 0;
    return strstr(buf, "\"tool\":\"manager\"") != NULL;
}

/* Prefer config local_host; if 127.0.0.1 is hijacked, use the outbound LAN IPv4. */
static void resolve_local_host(void) {
    char lan[64] = {0};
    SOCKET s;
    struct sockaddr_in peer, local;
    int len = sizeof(local);
    if (gateway_is_ours(g.local_host, g.local_port)) return;
    if (strcmp(g.local_host, "127.0.0.1") != 0 && gateway_is_ours("127.0.0.1", g.local_port)) {
        snprintf(g.local_host, sizeof(g.local_host), "127.0.0.1");
        return;
    }
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &peer.sin_addr);
    connect(s, (struct sockaddr *)&peer, sizeof(peer));
    memset(&local, 0, sizeof(local));
    if (getsockname(s, (struct sockaddr *)&local, &len) == 0)
        inet_ntop(AF_INET, &local.sin_addr, lan, sizeof(lan));
    closesocket(s);
    if (lan[0] && strcmp(lan, "0.0.0.0") != 0 && gateway_is_ours(lan, g.local_port)) {
        snprintf(g.local_host, sizeof(g.local_host), "%s", lan);
        printf("[tunnel] local_host -> %s (loopback not manager)\n", g.local_host);
        fflush(stdout);
    }
}

/* Worker entry: port-tunnel.exe --worker --local N --rmin A --rmax B ... */
int worker_main(int argc, char **argv) {
    WSADATA wsa;
    HANDLE th;
    int i;
    char hostbuf[64] = {0};

    memset(&g, 0, sizeof(g));
    snprintf(g.server_addr, sizeof(g.server_addr), "%s", PT_SERVER_ADDR);
    g.server_port = PT_SERVER_PORT;
    snprintf(g.token, sizeof(g.token), "%s", PT_TOKEN);
    g.dashboard_port = PT_DASHBOARD_PORT;
    snprintf(g.dashboard_user, sizeof(g.dashboard_user), "%s", PT_DASHBOARD_USER);
    snprintf(g.dashboard_password, sizeof(g.dashboard_password), "%s", PT_DASHBOARD_PASSWORD);
    snprintf(g.local_host, sizeof(g.local_host), "127.0.0.1");
    g.local_port = 3389;
    g.remote_port_min = 33800;
    g.remote_port_max = 33899;
    g.prefer_remote = 33890;
    snprintf(g.proxy_name, sizeof(g.proxy_name), "port-tunnel");
    snprintf(g.proxy_type, sizeof(g.proxy_type), "tcp");

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--local") == 0 && i + 1 < argc) g.local_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--rmin") == 0 && i + 1 < argc) g.remote_port_min = atoi(argv[++i]);
        else if (strcmp(argv[i], "--rmax") == 0 && i + 1 < argc) g.remote_port_max = atoi(argv[++i]);
        else if (strcmp(argv[i], "--prefer") == 0 && i + 1 < argc) g.prefer_remote = atoi(argv[++i]);
        else if (strcmp(argv[i], "--last") == 0 && i + 1 < argc) g.last_remote_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
            snprintf(g.proxy_name, sizeof(g.proxy_name), "%s", argv[++i]);
        else if (strcmp(argv[i], "--status") == 0 && i + 1 < argc)
            snprintf(g.status_path, sizeof(g.status_path), "%s", argv[++i]);
        else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            snprintf(g.local_host, sizeof(g.local_host), "%s", argv[++i]);
        else if (strcmp(argv[i], "--proto") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "udp") == 0)
                snprintf(g.proxy_type, sizeof(g.proxy_type), "udp");
            else
                snprintf(g.proxy_type, sizeof(g.proxy_type), "tcp");
        }
    }

    if (gethostname(hostbuf, sizeof(hostbuf) - 1) != 0) snprintf(hostbuf, sizeof(hostbuf), "pc");
    if (strcmp(g.proxy_name, "port-tunnel") == 0)
        snprintf(g.proxy_name, sizeof(g.proxy_name), "pt-%s-%d", hostbuf, g.local_port);

    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitializeCriticalSection(&g.mu);
    set_err("connecting");
    th = CreateThread(NULL, 0, frp_thread, NULL, 0, NULL);
    if (!th) return 1;
    for (;;) {
        if (WaitForSingleObject(th, 500) == WAIT_OBJECT_0) break;
        /* parent death: Job Object kills us; also check stop via status dir lock optional */
    }
    CloseHandle(th);
    return 0;
}
