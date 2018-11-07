#include "decode.h"

#include <err.h>
#include <errno.h>
#include "common.h"

static int
validate(asn_TYPE_descriptor_t const *descriptor, void *result)
{
	char error_msg[256];
	size_t error_msg_size;
	int error;

	/* The lib's inbuilt validations. (Probably not much.) */
	error_msg_size = sizeof(error_msg);
	error = asn_check_constraints(descriptor, result, error_msg,
	    &error_msg_size);
	if (error == -1) {
		warnx("Error validating ASN.1 object: %s", error_msg);
		return -EINVAL;
	}

	return 0;
}

int
asn1_decode(const void *buffer, size_t buffer_size,
    asn_TYPE_descriptor_t const *descriptor, void **result)
{
	asn_dec_rval_t rval;
	int error;

	*result = NULL;

	rval = ber_decode(0, descriptor, result, buffer, buffer_size);
	if (rval.code != RC_OK) {
		/* TODO if rval.code == RC_WMORE (1), more work is needed */
		warnx("Error decoding ASN.1 object: %d", rval.code);
		/* Must free partial object according to API contracts. */
		ASN_STRUCT_FREE(*descriptor, *result);
		return -EINVAL;
	}

	error = validate(descriptor, *result);
	if (error) {
		ASN_STRUCT_FREE(*descriptor, *result);
		return error;
	}

	return 0;
}

int
asn1_decode_any(ANY_t *any,
    asn_TYPE_descriptor_t const *descriptor,
    void **result)
{
	return asn1_decode(any->buf, any->size, descriptor, result);
}

int
asn1_decode_octet_string(OCTET_STRING_t *string,
    asn_TYPE_descriptor_t const *descriptor,
    void **result)
{
	return asn1_decode(string->buf, string->size, descriptor, result);
}

int
asn1_decode_fc(struct file_contents *fc,
    asn_TYPE_descriptor_t const *descriptor,
    void **result)
{
	return asn1_decode(fc->buffer, fc->buffer_size, descriptor, result);
}
