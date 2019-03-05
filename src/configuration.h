#ifndef _SRC_CONFIGURATION_H_
#define _SRC_CONFIGURATION_H_

#include <netdb.h>

int config_init(char const *);
void config_cleanup(void);

struct addrinfo const *config_get_server_addrinfo(void);
char const *config_get_server_port(void);
char const *config_get_vrps_location(void);
int config_get_vrps_check_interval(void);
int config_get_refresh_interval(void);
int config_get_retry_interval(void);
int config_get_expire_interval(void);

#endif /* _SRC_CONFIGURATION_H_ */
