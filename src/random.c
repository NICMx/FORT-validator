#include "random.h"

#include <stdlib.h>
#include <time.h>

void
random_init(void)
{
	/*
	 * time() has second precision, which is fine.
	 * I don't think that anyone will legitimately need to run this program
	 * more than once a second.
	 */
	srandom(time(NULL));
}

/**
 * Assumes 0 <= max <= RAND_MAX
 * Returns in the closed interval [0, max]
 *
 * Source: https://stackoverflow.com/questions/2509679
 */
long random_at_most(long max)
{
	/* max <= RAND_MAX < ULONG_MAX, so this is okay. */
	unsigned long num_bins = (unsigned long) max + 1;
	unsigned long num_rand = (unsigned long) RAND_MAX + 1;
	unsigned long bin_size = num_rand / num_bins;
	unsigned long defect = num_rand % num_bins;
	long x;

	do {
		x = random();
	/* This is carefully written not to overflow */
	} while (num_rand - defect <= (unsigned long) x);

	/* Truncated division is intentional */
	return x / bin_size;
}
