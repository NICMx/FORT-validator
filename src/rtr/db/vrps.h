#ifndef SRC_VRPS_H_
#define SRC_VRPS_H_

#include <stdbool.h>
#include "data_structure/array_list.h"
#include "rrdp/rrdp_objects.h"
#include "rtr/db/delta.h"

/*
 * Deltas that share a serial.
 */
struct delta_group {
	serial_t serial;
	struct deltas *deltas;
};

void deltagroup_cleanup(struct delta_group *);

DEFINE_ARRAY_LIST_STRUCT(deltas_db, struct delta_group);
DECLARE_ARRAY_LIST_FUNCTIONS(deltas_db, struct delta_group)

int vrps_init(void);
void vrps_destroy(void);

int vrps_update(bool *);

/*
 * The following three functions return -EAGAIN when vrps_update() has never
 * been called, or while it's still building the database.
 * Handle gracefully.
 */

int vrps_foreach_base(vrp_foreach_cb, router_key_foreach_cb, void *);
int vrps_get_deltas_from(serial_t, serial_t *, struct deltas_db *);
int get_last_serial_number(serial_t *);

int vrps_foreach_filtered_delta(struct deltas_db *, delta_vrp_foreach_cb,
    delta_router_key_foreach_cb, void *);

int handle_roa_v4(uint32_t, struct ipv4_prefix const *, uint8_t, void *);
int handle_roa_v6(uint32_t, struct ipv6_prefix const *, uint8_t, void *);
int handle_router_key(unsigned char const *, uint32_t, unsigned char const *,
    void *);

rrdp_uri_cmp_result_t rrdp_uri_cmp(char const *, char const *,
    unsigned long);
int rrdp_uri_update(char const *, char const *, unsigned long);
int rrdp_uri_get_serial(char const *, unsigned long *);
int rrdp_uri_get_last_update(char const *, long *);
int rrdp_uri_set_last_update(char const *);
bool rrdp_uri_visited(char const *);
int rrdp_uri_mark_visited(char const *);

uint16_t get_current_session_id(uint8_t);

#endif /* SRC_VRPS_H_ */
