#include "decode.h"

#include <errno.h>
#include "common.h"
#include "log.h"

static int
validate(struct validation *state, asn_TYPE_descriptor_t const *descriptor,
    void *result)
{
	char error_msg[256];
	size_t error_msg_size;
	int error;

	/* The lib's inbuilt validations. (Probably not much.) */
	error_msg_size = sizeof(error_msg);
	error = asn_check_constraints(descriptor, result, error_msg,
	    &error_msg_size);
	if (error == -1) {
		pr_err(state, "Error validating ASN.1 object: %s", error_msg);
		return -EINVAL;
	}

	return 0;
}

int
asn1_decode(struct validation *state, const void *buffer, size_t buffer_size,
    asn_TYPE_descriptor_t const *descriptor, void **result)
{
	asn_dec_rval_t rval;
	int error;

	*result = NULL;

	rval = ber_decode(0, descriptor, result, buffer, buffer_size);
	if (rval.code != RC_OK) {
		/* TODO if rval.code == RC_WMORE (1), more work is needed */
		pr_err(state, "Error decoding ASN.1 object: %d", rval.code);
		/* Must free partial object according to API contracts. */
		ASN_STRUCT_FREE(*descriptor, *result);
		return -EINVAL;
	}

	error = validate(state, descriptor, *result);
	if (error) {
		ASN_STRUCT_FREE(*descriptor, *result);
		return error;
	}

	return 0;
}

int
asn1_decode_any(struct validation *state, ANY_t *any,
    asn_TYPE_descriptor_t const *descriptor, void **result)
{
	return asn1_decode(state, any->buf, any->size, descriptor, result);
}

int
asn1_decode_octet_string(struct validation *state, OCTET_STRING_t *string,
    asn_TYPE_descriptor_t const *descriptor, void **result)
{
	return asn1_decode(state, string->buf, string->size, descriptor,
	    result);
}

int
asn1_decode_fc(struct validation *state, struct file_contents *fc,
    asn_TYPE_descriptor_t const *descriptor, void **result)
{
	return asn1_decode(state, fc->buffer, fc->buffer_size, descriptor,
	    result);
}
