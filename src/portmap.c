#include "portmap.h"

/*
 * 外网端口规则（每本机口固定 100 个候选，TCP ≤65535）：
 *
 * 1) L∈[1,654]  → [L*100, L*100+99]     例 22→2200-2299
 * 2) L∈[655,6553]→ 含 L*10 的整百段      例 3389→33800-33899（优先 33890）
 * 3) 其余        → 40000+(L%350)*100 起 100 口（折叠）
 */
void pt_port_pool(int local_port, int *min_out, int *max_out, int *prefer_out) {
    long p100, p10;
    int minv, maxv, prefer = 0;

    if (local_port < 1) local_port = 1;
    if (local_port > 65535) local_port = 65535;

    p100 = (long)local_port * 100L;
    if (p100 + 99L <= 65535L) {
        minv = (int)p100;
        maxv = (int)p100 + 99;
        prefer = minv; /* 优先 xx00，也可理解为整段起点 */
        goto out;
    }

    p10 = (long)local_port * 10L;
    if (p10 + 9L <= 65535L) {
        minv = (int)((p10 / 100L) * 100L);
        if (minv + 99 > 65535) minv = 65400;
        if (minv < 1024) minv = 1024;
        maxv = minv + 99;
        prefer = (int)p10; /* 3389 → 33890 */
        if (prefer < minv || prefer > maxv) prefer = minv;
        goto out;
    }

    {
        int slot = local_port % 350;
        minv = 40000 + slot * 100;
        if (minv + 99 > 65535) minv = 65400;
        maxv = minv + 99;
        prefer = minv;
    }

out:
    if (min_out) *min_out = minv;
    if (max_out) *max_out = maxv;
    if (prefer_out) *prefer_out = prefer;
}
