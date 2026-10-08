#ifndef COMMON_CONFIG_STRING_ARRAY_H_
#define COMMON_CONFIG_STRING_ARRAY_H_

#include "common/config/types.h"

struct string_array {
	/* BTW: The array size can be zero, in which case this will be NULL. */
	char **array;
	size_t length;
};

extern const struct global_type gt_string_array;

void string_array_init(struct string_array *, char const *const *, size_t);
void string_array_cleanup(struct string_array *);

#endif /* COMMON_CONFIG_STRING_ARRAY_H_ */
