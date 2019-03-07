#ifndef SRC_CONFIG_STRING_ARRAY_H_
#define SRC_CONFIG_STRING_ARRAY_H_

#include <stddef.h>
#include "config/types.h"

struct string_array {
	char **array;
	size_t length;
};

extern const struct global_type gt_string_array;

#endif /* SRC_CONFIG_STRING_ARRAY_H_ */
