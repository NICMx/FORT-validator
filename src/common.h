#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

/* "I haven't implemented this yet." */
#define ENOTIMPLEMENTED 3173

typedef char const *validation_verdict;
extern validation_verdict const VV_CONTINUE;	/* "No issues yet" */
extern validation_verdict const VV_FAIL;	/* "Validation failed" */
extern validation_verdict const VV_BUSY;	/* "Try again later" */

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

#define CACHE_FILEMODE 0755

typedef int (*foreach_file_cb)(char const *, void *);
int foreach_file(char const *, char const *, bool, foreach_file_cb, void *);

time_t time_nonfatal(void);
time_t time_fatal(void);

/*
 * Careful with this; several of the conversion specification characters
 * documented in the Linux man page are not actually portable.
 */
#define FORT_TS_FORMAT "%Y-%m-%dT%H:%M:%SZ"
#define FORT_TS_LEN 21 /* strlen("YYYY-mm-ddTHH:MM:SSZ") + 1 */
int time2str(time_t, char *);
int str2time(char const *, time_t *);

void ts_now(struct timespec *);
int ts_cmp(struct timespec *, struct timespec *);
int ts_delta(struct timespec *, struct timespec *);
void ts_add(struct timespec *, struct timespec *, long);

char *hex2str(uint8_t const *, size_t);
int str2hex(char const *, uint8_t *);

#endif /* SRC_RTR_COMMON_H_ */
