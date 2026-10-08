#ifndef SRC_TYPES_ARRAY_H_
#define SRC_TYPES_ARRAY_H_

#include <stddef.h>

typedef size_t array_index;
#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

#endif /* SRC_TYPES_ARRAY_H_ */
