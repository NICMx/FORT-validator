#include "asn1/decode.h"

#include "asn1/asn1c/ber_decoder.h"
#include "log.h"

/* Decoded BER data */
struct ber_data {
	const unsigned char *src;
	size_t src_size;
	size_t consumed;
};

static int
validate(asn_TYPE_descriptor_t const *descriptor, void *result, bool log)
{
	char errmsg[256];
	size_t errlen;

	/* The lib's inbuilt validations. (Probably not much.) */
	errlen = sizeof(errmsg);
	if (asn_check_constraints(descriptor, result, errmsg, &errlen) < 0) {
		if (log)
			pr_val_err("Error validating ASN.1 object: %s", errmsg);
		return EINVAL;
	}

	return 0;
}

int
asn1_decode(const void *buffer, size_t buffer_size,
    asn_TYPE_descriptor_t const *descriptor, void **result, bool log)
{
	asn_dec_rval_t rval;
	int error;

	*result = NULL;

	rval = ber_decode(descriptor, result, buffer, buffer_size);
	if (rval.code != RC_OK) {
		/* Must free partial object according to API contracts. */
		ASN_STRUCT_FREE(*descriptor, *result);
		/* We expect the data to be complete; RC_WMORE is an error. */
		if (log)
			pr_val_err("Error '%u' decoding ASN.1 object around byte %zu",
			    rval.code, rval.consumed);
		return EINVAL;
	}

	error = validate(descriptor, *result, log);
	if (error) {
		ASN_STRUCT_FREE(*descriptor, *result);
		return error;
	}

	return 0;
}

int
asn1_decode_any(ANY_t *any, asn_TYPE_descriptor_t const *descriptor,
    void **result, bool log)
{
	return (any != NULL)
	    ? asn1_decode(any->buf, any->size, descriptor, result, log)
	    : pr_val_err("ANY '%s' is NULL.", descriptor->name);
}

int
asn1_decode_octet_string(OCTET_STRING_t *string,
    asn_TYPE_descriptor_t const *descriptor, void **result, bool log)
{
	return (string != NULL)
	    ? asn1_decode(string->buf, string->size, descriptor, result, log)
	    : pr_val_err("Octet String '%s' is NULL.", descriptor->name);
}

/*
 * TODO (next iteration) There's no need to load the entire file into memory.
 * ber_decode() can take an incomplete buffer, in which case it returns
 * RC_WMORE.
 */
int
asn1_decode_fc(struct file_contents *fc,
    asn_TYPE_descriptor_t const *descriptor, void **result, bool log)
{
	return asn1_decode(fc->buf, fc->buflen, descriptor, result, log);
}
