#ifndef VALIDATOR_ASN1_DECODE_H_
#define VALIDATOR_ASN1_DECODE_H_

#include "common/file.h"
#include "common/types/address.h"
#include "validator/asn1/asn1c/ANY.h"
#include "validator/asn1/asn1c/IPAddressRange.h"

int asn1_decode(const void *, size_t, asn_TYPE_descriptor_t const *, void **,
    bool);
int asn1_decode_any(ANY_t *, asn_TYPE_descriptor_t const *, void **, bool);
int asn1_decode_octet_string(OCTET_STRING_t *, asn_TYPE_descriptor_t const *,
    void **, bool);
int asn1_decode_fc(struct file_contents *, asn_TYPE_descriptor_t const *,
    void **, bool);

int prefix4_decode(IPAddress_t const *, struct ipv4_prefix *);
int prefix6_decode(IPAddress_t const *, struct ipv6_prefix *);
int range4_decode(IPAddressRange_t const *, struct ipv4_range *);
int range6_decode(IPAddressRange_t const *, struct ipv6_range *);

#endif /* VALIDATOR_ASN1_DECODE_H_ */
