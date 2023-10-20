#ifndef RTR_RTR_H_
#define RTR_RTR_H_

int rtr_start(void);
void rtr_stop(void);

typedef int (*rtr_foreach_client_cb)(int, int, void *);
int rtr_foreach_client(rtr_foreach_client_cb, void *);

#endif /* RTR_RTR_H_ */
