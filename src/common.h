#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

#include <pthread.h>
#include <semaphore.h>

/* "I think that this is not supposed to be implemented." */
#define ENOTSUPPORTED 3172
/* "I haven't implemented this yet." */
#define ENOTIMPLEMENTED 3173
/*
 * "URI was not RSYNC; ignore it."
 * Not really an error. The RFCs usually declare URI lists; usually only one of
 * them is required to be RSYNC and the others should be skipped (until we
 * start supporting them.)
 */
#define ENOTRSYNC 3174

/*
 * If you're wondering why I'm not using -abs(error), it's because abs(INT_MIN)
 * overflows, so gcc complains sometimes.
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

/** Also boilerplate. */
int close_thread(pthread_t thread, char const *what);

typedef int (*process_file_cb)(char const *, void *);
int process_dir_files(char const *, char const *, process_file_cb, void *);

#endif /* SRC_RTR_COMMON_H_ */
