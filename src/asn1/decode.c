#include "asn1/decode.h"

#include "asn1/asn1c/ber_decoder.h"
#include "asn1/asn1c/constraints.h"
#include "common.h"
#include "incidence.h"
#include "log.h"

#define COND_LOG(log, pr) (log ? pr : -EINVAL)

/* Decoded BER data */
struct ber_data {
	const unsigned char *src;
	size_t src_size;
	size_t consumed;
};

static int
validate(asn_TYPE_descriptor_t const *descriptor, void *result, bool log)
{
	char error_msg[256];
	size_t error_msg_size;
	int error;

	/* The lib's inbuilt validations. (Probably not much.) */
	error_msg_size = sizeof(error_msg);
	error = asn_check_constraints(descriptor, result, error_msg,
	    &error_msg_size);
	if (error == -1)
		return COND_LOG(log,
		    pr_val_err("Error validating ASN.1 object: %s", error_msg));

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
		return COND_LOG(log,
		    pr_val_err("Error '%u' decoding ASN.1 object around byte %zu",
		        rval.code, rval.consumed));
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
	return asn1_decode(any->buf, any->size, descriptor, result, log);
}

int
asn1_decode_octet_string(OCTET_STRING_t *string,
    asn_TYPE_descriptor_t const *descriptor, void **result, bool log)
{
	return asn1_decode(string->buf, string->size, descriptor, result, log);
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
	return asn1_decode(fc->buffer, fc->buffer_size, descriptor, result, log);
}
