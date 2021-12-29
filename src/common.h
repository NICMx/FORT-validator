#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

#include <pthread.h>
#include <time.h>

/* "I think that this is not supposed to be implemented." */
#define ENOTSUPPORTED 3172

/*
 * If you're wondering why I'm not using -abs(error), it's because abs(INT_MIN)
 * overflows, so gcc complains sometimes.
 *
 * BE CAREFUL ABOUT DOUBLE EVALUATION.
 */
#define ENSURE_NEGATIVE(error) (((error) < 0) ? (error) : -(error))

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

/*
 * rwlock wrappers. They are just a bunch of boilerplate, and removal of
 * unrecoverable resulting error codes.
 */
int rwlock_read_lock(pthread_rwlock_t *);
void rwlock_write_lock(pthread_rwlock_t *);
void rwlock_unlock(pthread_rwlock_t *);

int get_current_time(time_t *);

#endif /* SRC_RTR_COMMON_H_ */
