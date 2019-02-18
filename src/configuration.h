#ifndef _SRC_CONFIGURATION_H_
#define _SRC_CONFIGURATION_H_

#include <netdb.h>

int config_init(char const *);
void config_cleanup(void);

struct addrinfo const *config_get_server_addrinfo(void);
char const *config_get_server_port(void);
char const *config_get_vrps_location(void);

#endif /* _SRC_CONFIGURATION_H_ */
