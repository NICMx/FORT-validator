#ifndef SRC_TYPES_FNSTACK_H_
#define SRC_TYPES_FNSTACK_H_

#include "types/map.h"

void fnstack_setup(void); /* This function does not need cleanup. */
void fnstack_init(void); /* This function does not need cleanup. */

void fnstack_push(char const *);
void fnstack_push_map(struct cache_mapping const *);
char const *fnstack_peek(void);
void fnstack_pop(void);

#endif /* SRC_TYPES_FNSTACK_H_ */
