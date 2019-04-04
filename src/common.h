#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

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

void read_lock(sem_t *, sem_t *, unsigned int *);
void read_unlock(sem_t *, sem_t *, unsigned int *);

#endif /* SRC_RTR_COMMON_H_ */
