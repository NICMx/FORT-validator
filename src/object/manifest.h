#ifndef SRC_OBJECT_MANIFEST_H_
#define SRC_OBJECT_MANIFEST_H_

#include <stdbool.h>
#include "state.h"

bool is_manifest(char const *);
int handle_manifest(struct validation *, char const *);

#endif /* SRC_OBJECT_MANIFEST_H_ */
