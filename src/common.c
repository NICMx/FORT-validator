#include "common.h"

#include "log.h"

int
rwlock_read_lock(pthread_rwlock_t *lock)
{
	int error;

	error = pthread_rwlock_rdlock(lock);
	switch (error) {
	case 0:
		return error;
	case EAGAIN:
		pr_op_err("There are too many threads; I can't modify the database.");
		return error;
	}

	/*
	 * EINVAL, EDEADLK and unknown nonstandard error codes.
	 * EINVAL, EDEADLK indicate serious programming errors. And it's
	 * probably safest to handle the rest the same.
	 * pthread_rwlock_rdlock() failing like this is akin to `if` failing;
	 * we're screwed badly, so let's just pull the trigger.
	 */
	pr_crit("pthread_rwlock_rdlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
	    error);
}

void
rwlock_write_lock(pthread_rwlock_t *lock)
{
	int error;

	/*
	 * POSIX says that the only available errors are EINVAL and EDEADLK.
	 * Both of them indicate serious programming errors.
	 */
	error = pthread_rwlock_wrlock(lock);
	if (error)
		pr_crit("pthread_rwlock_wrlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    error);
}

void
rwlock_unlock(pthread_rwlock_t *lock)
{
	int error;

	/*
	 * POSIX says that the only available errors are EINVAL and EPERM.
	 * Both of them indicate serious programming errors.
	 */
	error = pthread_rwlock_unlock(lock);
	if (error)
		pr_crit("pthread_rwlock_unlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    error);
}

int
get_current_time(time_t *result)
{
	time_t now;

	now = time(NULL);
	if (now == ((time_t) -1))
		return pr_val_errno(errno, "Error getting the current time");

	*result = now;
	return 0;
}
