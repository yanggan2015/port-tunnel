/* Mainstream service presets for quick checkbox UI. */
#ifndef PORT_TUNNEL_PRESETS_H
#define PORT_TUNNEL_PRESETS_H

typedef struct {
    const char *id;    /* stable id, e.g. "rdp" */
    const char *name;  /* UI label */
    int port;
    int udp;           /* 0=TCP 1=UDP */
} PtPreset;

/* Keep list short but cover common ops / net / DB. */
static const PtPreset PT_PRESETS[] = {
    {"rdp",       "RDP 远程桌面",     3389,  0},
    {"ssh",       "SSH",              22,    0},
    {"http",      "HTTP",             80,    0},
    {"https",     "HTTPS",            443,   0},
    {"vnc",       "VNC",              5900,  0},
    {"smb",       "SMB 文件共享",     445,   0},
    {"mysql",     "MySQL",            3306,  0},
    {"postgres",  "PostgreSQL",       5432,  0},
    {"redis",     "Redis",            6379,  0},
    {"mongo",     "MongoDB",          27017, 0},
    {"mqtt",      "MQTT",             1883,  0},
    {"rdp-udp",   "RDP UDP",          3389,  1},
    {"dns",       "DNS",              53,    1},
    {"ntp",       "NTP",              123,   1},
    {"snmp",      "SNMP",             161,   1},
    {"openvpn",   "OpenVPN",          1194,  1},
    {"wireguard", "WireGuard",        51820, 1},
    {"quic",      "HTTP3/QUIC",       443,   1},
};
#define PT_PRESET_COUNT ((int)(sizeof(PT_PRESETS) / sizeof(PT_PRESETS[0])))

#endif
