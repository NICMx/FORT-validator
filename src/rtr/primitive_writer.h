#ifndef RTR_PRIMITIVE_WRITER_H_
#define RTR_PRIMITIVE_WRITER_H_

#include <netinet/in.h>

__BEGIN_DECLS
unsigned char *write_int8(unsigned char *, u_int8_t);
unsigned char *write_int16(unsigned char *, u_int16_t);
unsigned char *write_int32(unsigned char *, u_int32_t);
unsigned char *write_in_addr(unsigned char *, struct in_addr);
unsigned char *write_in6_addr(unsigned char *, struct in6_addr);
__END_DECLS

#endif /* RTR_PRIMITIVE_WRITER_H_ */
