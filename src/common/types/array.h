#ifndef COMMON_TYPES_ARRAY_H_
#define COMMON_TYPES_ARRAY_H_

#include <stddef.h>

typedef size_t array_index;
#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

#endif /* COMMON_TYPES_ARRAY_H_ */
