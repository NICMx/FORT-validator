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
	 * TODO Everyone uses this algorithm, but at a quick glance, it doesn't
	 * seem to match RFC 7935's public key algorithm. Wtf?
	 */
	return NID_rsaEncryption;
}
