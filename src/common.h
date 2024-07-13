#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

/* "I think this is not supposed to be implemented." */
#define ENOTSUPPORTED 3172
/* "I haven't implemented this yet." */
#define ENOTIMPLEMENTED 3173
/* "URI was not RSYNC." */
#define ENOTRSYNC 3174
/* "URI was not HTTPS." */
#define ENOTHTTPS 3175

/*
 * If you're wondering why I'm not using -abs(error), it's because abs(INT_MIN)
 * overflows, so gcc complains sometimes.
 *
 * BE CAREFUL ABOUT DOUBLE EVALUATION.
 */
#define ENSURE_NEGATIVE(error) (((error) < 0) ? (error) : -(error))

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

bool str_starts_with(char const *, char const *);
bool str_ends_with(char const *, char const *);

void panic_on_fail(int, char const *);

/*
 * Mutex wrappers. They are just a bunch of boilerplate, and removal of
 * unrecoverable resulting error codes.
 */
void mutex_lock(pthread_mutex_t *);
void mutex_unlock(pthread_mutex_t *);

/*
 * rwlock wrappers. They are just a bunch of boilerplate, and removal of
 * unrecoverable resulting error codes.
 */
int rwlock_read_lock(pthread_rwlock_t *);
void rwlock_write_lock(pthread_rwlock_t *);
void rwlock_unlock(pthread_rwlock_t *);

typedef int (*foreach_file_cb)(char const *, void *);
int foreach_file(char const *, char const *, bool, foreach_file_cb, void *);

// XXX
bool valid_file_or_dir(char const *, bool);

int mkdir_p(char const *, bool, mode_t);
int delete_dir_recursive_bottom_up(char const *);

int get_current_time(time_t *);

#endif /* SRC_RTR_COMMON_H_ */
