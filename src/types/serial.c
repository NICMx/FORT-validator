#include "types/serial.h"

/*
 * Returns s1 < s2 , according to RFC 1982 serial arithmetic.
 */
bool
serial_lt(serial_t s1, serial_t s2)
{
	if (s1 == s2)
		return false;

	return ((s1 < s2) && ((s2 - s1) < 0x80000000u)) ||
	       ((s1 > s2) && ((s1 - s2) > 0x80000000u));
}
