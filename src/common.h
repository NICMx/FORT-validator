#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

#include <pthread.h>
#include <stdbool.h>
#include <time.h>

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
 * "URI was not HTTPS; ignore it."
 * Not necessarily an error (just as ENOTRSYNC), since both type of URIs can
 * still coexist in most scenarios.
 */
#define ENOTHTTPS 3175

/*
 * A request made to a server (eg. rsync, http) has failed, even after retrying
 */
#define EREQFAILED 3176

/*
 * If you're wondering why I'm not using -abs(error), it's because abs(INT_MIN)
 * overflows, so gcc complains sometimes.
 *
 * BE CAREFUL ABOUT DOUBLE EVALUATION.
 */
#define ENSURE_NEGATIVE(error) (((error) < 0) ? (error) : -(error))

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

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

typedef int (*process_file_cb)(char const *, void *);
int process_file_or_dir(char const *, char const *, bool, process_file_cb,
    void *);

typedef int (*pr_errno_cb)(const char *, ...);
bool valid_file_or_dir(char const *, bool, bool, pr_errno_cb);

int create_dir_recursive(char const *);
int delete_dir_recursive_bottom_up(char const *);

int get_current_time(time_t *);

int map_uri_to_local(char const *, char const*, char const *, char **);

#endif /* SRC_RTR_COMMON_H_ */
