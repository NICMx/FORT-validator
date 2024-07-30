#ifndef SRC_TYPES_ARRAY_H_
#define SRC_TYPES_ARRAY_H_

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

typedef size_t array_index;
#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

#endif /* SRC_TYPES_ARRAY_H_ */
