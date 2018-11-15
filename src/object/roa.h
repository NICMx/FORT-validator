#ifndef SRC_OBJECT_ROA_H_
#define SRC_OBJECT_ROA_H_

#include <stdbool.h>
#include "state.h"

bool is_roa(char const *);
int handle_roa(struct validation *, char const *);

#endif /* SRC_OBJECT_ROA_H_ */
