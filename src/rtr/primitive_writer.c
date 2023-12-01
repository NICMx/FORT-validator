#include "rtr/primitive_writer.h"

unsigned char *
write_uint8(unsigned char *buf, uint8_t value)
{
	buf[0] = value;
	return buf + 1;
}

/** Big Endian. */
unsigned char *
write_uint16(unsigned char *buf, uint16_t value)
{
	buf[0] = value >> 8;
	buf[1] = value;
	return buf + 2;
}

/** Big Endian. */
unsigned char *
write_uint32(unsigned char *buf, uint32_t value)
{
	buf[0] = value >> 24;
	buf[1] = value >> 16;
	buf[2] = value >> 8;
	buf[3] = value;
	return buf + 4;
}

unsigned char *
write_in_addr(unsigned char *buf, struct in_addr value)
{
	return write_uint32(buf, ntohl(value.s_addr));
}

unsigned char *
write_in6_addr(unsigned char *buf, struct in6_addr const *value)
{
	int i;
	for (i = 0; i < 16; i++)
		buf = write_uint8(buf, value->s6_addr[i]);
	return buf;
}
