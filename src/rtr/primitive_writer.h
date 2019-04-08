#ifndef RTR_PRIMITIVE_WRITER_H_
#define RTR_PRIMITIVE_WRITER_H_

#include <netinet/in.h>

__BEGIN_DECLS
char *write_int8(char *, uint8_t);
char *write_int16(char *, uint16_t);
char *write_int32(char *, uint32_t);
char *write_in_addr(char *, struct in_addr);
char *write_in6_addr(char *, struct in6_addr);
__END_DECLS

#endif /* RTR_PRIMITIVE_WRITER_H_ */
