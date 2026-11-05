#ifndef SRC_RTR_DB_VPT_H_
#define SRC_RTR_DB_VPT_H_

#include "types/address.h"
#include "types/aspa.h"
#include "types/router_key.h"
#include "types/serial.h"
#include "types/vrp.h"

struct vp_table;

struct vp_table *vpt_create(void);
void vpt_destroy(struct vp_table *);

int vpt_join(struct vp_table *, struct vp_table *);

unsigned int vpt_vrp_count(struct vp_table *);
unsigned int vpt_vrp4_count(struct vp_table *);
unsigned int vpt_vrp6_count(struct vp_table *);
unsigned int vpt_rk_count(struct vp_table *);
unsigned int vpt_aspa_count(struct vp_table *);
uint16_t vpt_session(struct vp_table *);
serial_t vpt_serial(struct vp_table *);

void vpt_sort(struct vp_table *);
int vpt_cache(struct vp_table *);

typedef int (*vrp_foreach_cb)(struct vrp const *, void *);
int vpt_foreach_vrp(struct vp_table const *, vrp_foreach_cb, void *);
void vpt_rm_vrp(struct vp_table *, struct vrp const *);

typedef int (*rk_foreach_cb)(struct router_key const *, void *);
int vpt_foreach_rk(struct vp_table const *, rk_foreach_cb, void *);
void vpt_rm_rk(struct vp_table *, struct router_key const *);

typedef int (*aspa_foreach_cb)(struct aspa const *, void *);
int vpt_foreach_aspa(struct vp_table const *, aspa_foreach_cb, void *);

int rtrhandler_handle_vrp4(struct vp_table *, uint32_t,
    struct ipv4_prefix const *, uint8_t);
int rtrhandler_handle_vrp6(struct vp_table *, uint32_t,
    struct ipv6_prefix const *, uint8_t);
int rtrhandler_handle_rk(struct vp_table *, unsigned char const *,
    uint32_t, unsigned char const *);
int rtrhandler_handle_aspa(struct vp_table *, struct aspa *);

#endif /* SRC_RTR_DB_VPT_H_ */
