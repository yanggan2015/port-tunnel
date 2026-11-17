#include "portmap.h"

/*
 * 外网端口规则（每本机口 100 候选 + 可选记忆 prefer）：
 *
 * 1) L∈[1,654]：池 [L*100, L*100+99]，prefer=L*100
 *    → 彼此不重叠；例 22→2200-2299
 *
 * 2) L≥655：不能再用 L*100（会溢出或与低位口撞车，如 338 与 3389）
 *    - prefer = L*10（若 ≤65535），如 3389→33890（好记，可落在池外）
 *    - 主池唯一：50000 + (L % 150)*100 … +99（50000-64999，150 槽）
 *    选口时 worker 会先试 prefer（允许跨段），再扫主池。
 */
void pt_port_pool(int local_port, int *min_out, int *max_out, int *prefer_out) {
    int minv, maxv, prefer = 0;

    if (local_port < 1) local_port = 1;
    if (local_port > 65535) local_port = 65535;

    if (local_port <= 654) {
        minv = local_port * 100;
        maxv = minv + 99;
        prefer = minv;
    } else {
        int slot = local_port % 150;
        minv = 50000 + slot * 100;
        if (minv + 99 > 65535) minv = 65400;
        maxv = minv + 99;
        {
            long p10 = (long)local_port * 10L;
            if (p10 >= 1024L && p10 <= 65535L) prefer = (int)p10;
            else prefer = minv;
        }
    }

    if (min_out) *min_out = minv;
    if (max_out) *max_out = maxv;
    if (prefer_out) *prefer_out = prefer;
}
