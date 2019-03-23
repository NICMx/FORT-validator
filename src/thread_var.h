#ifndef SRC_THREAD_VAR_H_
#define SRC_THREAD_VAR_H_

#include "state.h"

void thvar_init(void);

int state_store(struct validation *);
struct validation *state_retrieve(void);

void fnstack_init(void);
void fnstack_cleanup(void);

void fnstack_push(char const *);
void fnstack_push_uri(struct rpki_uri const *);
char const *fnstack_peek(void);
void fnstack_pop(void);

char const *v4addr2str(struct in_addr *addr);
char const *v4addr2str2(struct in_addr *addr);
char const *v6addr2str(struct in6_addr *addr);
char const *v6addr2str2(struct in6_addr *addr);

#endif /* SRC_THREAD_VAR_H_ */
