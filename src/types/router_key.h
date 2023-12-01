#ifndef SRC_TYPES_ROUTER_KEY_H_
#define SRC_TYPES_ROUTER_KEY_H_

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>

/*
 * SKI is always 20 bytes long rfc6487#section-4.8.2:
 * "The Key Identifier used for resource certificates is the 160-bit {...}"
 */
#define RK_SKI_LEN	20

/*
 * SPKI (subjectPublicKeyInfo) is 91 bytes long (considering TLVs):
 *   SEQUENCE subjectPublicKeyInfo: 2 (Tag & Length) + 89 (Value)
 *     Public key: 2 (TL) + 65 (V)
 *     SEQUENCE Algorithm: 2 (TL) + 19 (V)
 *       Algorithm OID: 2 (TL) + 7 (V) [oid: 1.2.840.10045.2.1]
 *       Algorithm param:  2 (TL) + 8 (V) [oid: 1.2.840.10045.3.1.7]
 */
#define RK_SPKI_LEN	91

/*
 * Router Key representation
 */
struct router_key {
	/* Lengths are constant (see RK_SKI_LEN, RK_SPKI_LEN) */
	unsigned char	ski[RK_SKI_LEN];
	uint32_t	as;
	unsigned char	spk[RK_SPKI_LEN];
};

typedef int (*router_key_foreach_cb)(struct router_key const *, void *);

void router_key_init(struct router_key *, unsigned char const *, uint32_t,
    unsigned char const *);
int router_key_print(struct router_key const *, void *);

#endif /* SRC_TYPES_ROUTER_KEY_H_ */
