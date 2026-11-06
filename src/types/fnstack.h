#ifndef SRC_THREAD_VAR_H_
#define SRC_THREAD_VAR_H_

#include "types/map.h"

int thvar_init(void); /* This function does not need cleanup. */

void fnstack_init(void);
void fnstack_cleanup(void);

void fnstack_push(char const *);
void fnstack_push_map(struct cache_mapping const *);
char const *fnstack_peek(void);
void fnstack_pop(void);

#endif /* SRC_THREAD_VAR_H_ */
