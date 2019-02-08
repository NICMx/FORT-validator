#ifndef SRC_ALGORITHM_H_
#define SRC_ALGORITHM_H_

/**
 * This file is an implementation of RFC 7935 (previously 6485) and its update,
 * 8208.
 *
 * It's just a bunch of functions that return the NIDs of the algorithms RPKI
 * validations are supposed to employ.
 */

int rpki_signature_algorithm(void);
int rpki_public_key_algorithm(void);

#endif /* SRC_ALGORITHM_H_ */
