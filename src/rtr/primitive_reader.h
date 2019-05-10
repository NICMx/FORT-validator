#ifndef RTR_PRIMITIVE_READER_H_
#define RTR_PRIMITIVE_READER_H_

#include <netinet/ip.h>

#include "common.h"

typedef char rtr_char;

struct pdu_reader {
	unsigned char *buffer;
	size_t size;
};

int pdu_reader_init(struct pdu_reader *, int, unsigned char *, size_t size);

int read_int8(struct pdu_reader *, uint8_t *);
int read_int16(struct pdu_reader *, uint16_t *);
int read_int32(struct pdu_reader *, uint32_t *);
int read_in_addr(struct pdu_reader *, struct in_addr *);
int read_in6_addr(struct pdu_reader *, struct in6_addr *);
int read_string(struct pdu_reader *, uint32_t, rtr_char **);
int read_bytes(struct pdu_reader *, unsigned char *, size_t);

#endif /* RTR_PRIMITIVE_READER_H_ */
