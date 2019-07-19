#ifndef SRC_OBJECT_ROUTER_KEY_H_
#define SRC_OBJECT_ROUTER_KEY_H_

#include <stdint.h>
#include <stdlib.h>

/*
 * SKI is always 20 bytes long rfc6487#section-4.8.2:
 * "The Key Identifier used for resource certificates is the 160-bit {...}"
 */
#define RK_SKI_LEN	20

/*
 * Subject key info with ref counter, use getters to fetch its data
 */
struct sk_info;

/*
 * Router Key representation
 */
struct router_key {
	uint32_t	as;
	struct sk_info	*sk;
};

int router_key_init(struct router_key *, unsigned char const *, uint32_t,
    unsigned char const *, size_t);
void router_key_cleanup(struct router_key *);

void sk_info_refget(struct sk_info *);
void sk_info_refput(struct sk_info *);

unsigned char *sk_info_get_ski(struct sk_info *);
unsigned char *sk_info_get_spk(struct sk_info *);
size_t sk_info_get_spk_len(struct sk_info *);

#endif /* SRC_OBJECT_ROUTER_KEY_H_ */
