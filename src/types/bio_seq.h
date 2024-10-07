#ifndef SRC_TYPES_BIO_SEQ_H_
#define SRC_TYPES_BIO_SEQ_H_

#include <openssl/bio.h>

int bioseq_setup(void);
void bioseq_teardown(void);

BIO *BIO_new_seq(BIO *, BIO *);

#endif /* SRC_TYPES_BIO_SEQ_H_ */
