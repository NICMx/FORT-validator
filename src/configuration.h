#ifndef _SRC_CONFIGURATION_H_
#define _SRC_CONFIGURATION_H_

#include "types.h"

struct rtr_config {
	/** The listener address of the RTR server. */
	struct ipv4_transport_addr ipv4_server_addr;
};


int read_config_from_file(char *, struct rtr_config **);


#endif /* _SRC_CONFIGURATION_H_ */
