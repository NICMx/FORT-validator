#ifndef SRC_TYPES_SERIAL_H_
#define SRC_TYPES_SERIAL_H_

#include <stdbool.h>
#include <stdint.h>

typedef uint32_t serial_t;

bool serial_lt(serial_t s1, serial_t s2);

#endif /* SRC_TYPES_SERIAL_H_ */
