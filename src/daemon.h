#ifndef SRC_DAEMON_H_
#define SRC_DAEMON_H_

#include "common.h"

init_verdict daemonize(void);
int drop_privileges(void);
void daemon_teardown(void);

#endif /* SRC_DAEMON_H_ */
