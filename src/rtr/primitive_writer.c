#include "primitive_writer.h"

char *
write_int8(char *buf, u_int8_t value)
{
	buf[0] = value;
	return buf + 1;
}

/** Big Endian. */
char *
write_int16(char *buf, u_int16_t value)
{
	buf[0] = value >> 8;
	buf[1] = value;
	return buf + 2;
}

/** Big Endian. */
char *
write_int32(char *buf, u_int32_t value)
{
	buf[0] = value >> 24;
	buf[1] = value >> 16;
	buf[2] = value >> 8;
	buf[3] = value;
	return buf + 4;
}

char *
write_in_addr(char *buf, struct in_addr value)
{
	return write_int32(buf, value.s_addr);
}

char *
write_in6_addr(char *buf, struct in6_addr value)
{
	buf = write_int32(buf, value.s6_addr32[0]);
	buf = write_int32(buf, value.s6_addr32[1]);
	buf = write_int32(buf, value.s6_addr32[2]);
	return write_int32(buf, value.s6_addr32[3]);
}
