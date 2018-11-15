#ifndef SRC_ASN1_DECODE_H_
#define SRC_ASN1_DECODE_H_

#include <libcmscodec/ANY.h>
#include <libcmscodec/constr_TYPE.h>
#include "file.h"
#include "state.h"

int asn1_decode(struct validation *, const void *, size_t,
    asn_TYPE_descriptor_t const *, void **);
int asn1_decode_any(struct validation *, ANY_t *, asn_TYPE_descriptor_t const *,
    void **);
int asn1_decode_octet_string(struct validation *, OCTET_STRING_t *,
    asn_TYPE_descriptor_t const *, void **);
int asn1_decode_fc(struct validation *, struct file_contents *,
    asn_TYPE_descriptor_t const *, void **);

#endif /* SRC_ASN1_DECODE_H_ */
