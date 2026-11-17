#ifndef PORT_TUNNEL_PORTMAP_H
#define PORT_TUNNEL_PORTMAP_H

#ifdef __cplusplus
extern "C" {
#endif

/* Local L -> remote pool [min,max] (100 ports). Prefer pick = prefer if >0. */
void pt_port_pool(int local_port, int *min_out, int *max_out, int *prefer_out);

#ifdef __cplusplus
}
#endif
#endif
