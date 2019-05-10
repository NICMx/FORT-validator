#ifndef SRC_VALIDATION_HANDLER_H_
#define SRC_VALIDATION_HANDLER_H_

#include "address.h"
#include "object/name.h"

struct validation_handler {
	/* All of these can be NULL. */

	int (*merge)(void *, void *);
	void *merge_arg;
	int (*reset)(void *);
	int (*traverse_down)(struct rfc5280_name *, void *);
	int (*traverse_up)(void *);
	int (*handle_roa_v4)(uint32_t, struct ipv4_prefix const *, uint8_t,
	    void *);
	int (*handle_roa_v6)(uint32_t, struct ipv6_prefix const *, uint8_t,
	    void *);
	void *arg;
};

int vhandler_merge(struct validation_handler *);
int vhandler_reset(struct validation_handler *);
int vhandler_traverse_down(struct rfc5280_name *);
int vhandler_traverse_up(void);
int vhandler_handle_roa_v4(uint32_t, struct ipv4_prefix const *, uint8_t);
int vhandler_handle_roa_v6(uint32_t, struct ipv6_prefix const *, uint8_t);

#endif /* SRC_VALIDATION_HANDLER_H_ */
