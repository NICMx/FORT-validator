#ifndef SRC_OBJECT_ROUTER_KEY_H_
#define SRC_OBJECT_ROUTER_KEY_H_

/*
 * Roouter Key representation
 */
struct router_key {
	unsigned char	*ski;
	size_t		ski_len;
	uint32_t	asn;
	unsigned char	*spk;
	size_t		spk_len;
};

#endif /* SRC_OBJECT_ROUTER_KEY_H_ */
