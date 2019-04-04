#include "common.h"

void
read_lock(sem_t *read, sem_t *write, unsigned int *reader_count)
{
	sem_wait(read);
	(*reader_count)++;
	if (*reader_count == 1)
		sem_wait(write);
	sem_post(read);
}

/*
 * MUST NOT be called without previously called 'read_lock' or done the same
 * things that such function does.
 */
void
read_unlock(sem_t *read, sem_t *write, unsigned int *reader_count)
{
	sem_wait(read);
	(*reader_count)--;
	if (*reader_count == 0) {
		sem_post(write);
	}
	sem_post(read);
}
