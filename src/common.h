#ifndef _SRC_COMMON_H_
#define _SRC_COMMON_H_

#include <semaphore.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define EUNIMPLEMENTED 566456

/*
 * FYI: The error functions are warn() and warnx().
 * warn() automatically appends the errno string message (strerror()), warnx()
 * does not.
 */

void read_lock(sem_t *, sem_t *, unsigned int *);
void read_unlock(sem_t *, sem_t *, unsigned int *);

#endif /* _SRC_COMMON_H_ */
