#ifndef SRC_THREAD_VAR_H_
#define SRC_THREAD_VAR_H_

#include "state.h"

int thvar_init(void); /* This function does not need cleanup. */

int state_store(struct validation *);
struct validation *state_retrieve(void);

void fnstack_init(void);
void fnstack_cleanup(void);

void fnstack_push(char const *);
void fnstack_push_uri(struct rpki_uri *);
char const *fnstack_peek(void);
void fnstack_pop(void);

void working_repo_init(void);
void working_repo_cleanup(void);

/* TODO (#78) remove? */
void working_repo_push(char const *);
char const *working_repo_peek(void);
void working_repo_pop(void);

/* Please remember that these functions can only be used during validations. */
char const *v4addr2str(struct in_addr const *);
char const *v4addr2str2(struct in_addr const *);
char const *v6addr2str(struct in6_addr const *);
char const *v6addr2str2(struct in6_addr const *);

#endif /* SRC_THREAD_VAR_H_ */
