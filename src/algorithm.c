#include "algorithm.h"

#include <openssl/obj_mac.h>

int
rpki_signature_algorithm(void)
{
	return NID_sha256WithRSAEncryption;
}

int
rpki_public_key_algorithm(void)
{
	/*
	 * TODO Everyone uses this algorithm, but the RFC says that it should
	 * be NID_sha256WithRSAEncryption. Wtf?
	 */
	return NID_rsaEncryption;
}
