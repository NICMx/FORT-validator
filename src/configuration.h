#ifndef _SRC_CONFIGURATION_H_
#define _SRC_CONFIGURATION_H_

#include "netdb.h"
#include <asm/types.h>

struct rtr_config {
	/** The listener address of the RTR server. */
	struct addrinfo *host_address;
	/** The listener port of the RTR server. */
	__u16 host_port;
};

void free_rtr_config(struct rtr_config *);
int read_config_from_file(char *, struct rtr_config **);


#endif /* _SRC_CONFIGURATION_H_ */
