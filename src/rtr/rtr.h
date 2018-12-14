#ifndef RTR_RTR_H_
#define RTR_RTR_H_

#include <netdb.h>
#include <asm/types.h>

#include "../common.h"

__BEGIN_DECLS
int rtr_listen(struct addrinfo *, __u16);
__END_DECLS

#endif /* RTR_RTR_H_ */
