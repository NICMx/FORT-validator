#ifndef SRC_ASN1_DECODE_H_
#define SRC_ASN1_DECODE_H_

#include "file.h"
#include "asn1/asn1c/ANY.h"
#include "asn1/asn1c/constr_TYPE.h"

int asn1_decode(const void *, size_t, asn_TYPE_descriptor_t const *, void **,
    bool, bool);
int asn1_decode_any(ANY_t *, asn_TYPE_descriptor_t const *, void **, bool,
    bool);
int asn1_decode_octet_string(OCTET_STRING_t *, asn_TYPE_descriptor_t const *,
    void **, bool, bool);
int asn1_decode_fc(struct file_contents *, asn_TYPE_descriptor_t const *,
    void **, bool, bool);

#endif /* SRC_ASN1_DECODE_H_ */
