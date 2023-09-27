#ifndef RTR_PRIMITIVE_WRITER_H_
#define RTR_PRIMITIVE_WRITER_H_

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>

unsigned char *write_int8(unsigned char *, uint8_t);
unsigned char *write_int16(unsigned char *, uint16_t);
unsigned char *write_int32(unsigned char *, uint32_t);
unsigned char *write_in_addr(unsigned char *, struct in_addr);
unsigned char *write_in6_addr(unsigned char *, struct in6_addr);

#endif /* RTR_PRIMITIVE_WRITER_H_ */
