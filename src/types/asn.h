#ifndef SRC_TYPES_ASN_H_
#define SRC_TYPES_ASN_H_

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>

struct asn_range {
	uint32_t min;
	uint32_t max;
};

#endif /* SRC_TYPES_ASN_H_ */
