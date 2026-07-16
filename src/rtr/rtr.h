#ifndef RTR_RTR_H_
#define RTR_RTR_H_

#include "rtr/meta.h"

int rtr_start(void);
void rtr_stop(void);

void rtr_notify(struct rtr_metadata *);

#endif /* RTR_RTR_H_ */
