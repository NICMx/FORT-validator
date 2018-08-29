#ifndef RTR_PRIMITIVE_READER_H_
#define RTR_PRIMITIVE_READER_H_

#include <netinet/ip.h>

#include "../common.h"

typedef char rtr_char;

__BEGIN_DECLS
int read_int8(int, u_int8_t *);
int read_int16(int, u_int16_t *);
int read_int32(int, u_int32_t *);
int read_in_addr(int, struct in_addr *);
int read_in6_addr(int, struct in6_addr *);
int read_string(int, rtr_char **);
__END_DECLS

#endif /* RTR_PRIMITIVE_READER_H_ */
