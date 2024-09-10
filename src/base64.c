#include "base64.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "alloc.h"
#include "log.h"

/* Simple decode base64 string. Returns true on success, false on failure. */
bool
base64_decode(char *in, size_t in_len, unsigned char **out, size_t *out_len)
{
	unsigned char *result;
	EVP_ENCODE_CTX *ctx;
	int outl;
	int status;

	if (in_len == 0)
		in_len = strlen(in);

	/*
	 * Will usually allocate more because of the newlines,
	 * but I'm at peace with it.
	 */
	result = pmalloc(EVP_DECODE_LENGTH(in_len));

	ctx = EVP_ENCODE_CTX_new();
	if (ctx == NULL)
		enomem_panic();

	EVP_DecodeInit(ctx);

	status = EVP_DecodeUpdate(ctx, result, &outl, (unsigned char *)in, in_len);
	if (status == -1)
		return false;

	*out_len = outl;

	status = EVP_DecodeFinal(ctx, result + outl, &outl);
	if (status != 1)
		return false;

	*out = result;
	*out_len += outl;
	return true;
}

/*
 * Decode a base64 encoded string (@str_encoded), the decoded value is
 * allocated at @result with a length of @result_len.
 *
 * Return 0 on success, or the error code if something went wrong. Don't forget
 * to free @result after a successful decoding.
 */
bool
base64url_decode(char const *str_encoded, unsigned char **result,
    size_t *result_len)
{
	char *str_copy;
	size_t encoded_len;
	size_t pad;
	size_t i;
	bool success;

	/*
	 * Apparently there isn't a base64url decoder, and there isn't
	 * much difference between base64 codification and base64url, just as
	 * stated in RFC 4648 section 5: "This encoding is technically
	 * identical to the previous one, except for the 62:nd and 63:rd
	 * alphabet character, as indicated in Table 2".
	 *
	 * The existing base64 can be used if the 62:nd and 63:rd base64url
	 * alphabet chars are replaced with the corresponding base64 chars, and
	 * also if we add the optional padding that the member should have.
	 */
	encoded_len = strlen(str_encoded);
	pad = (encoded_len % 4) > 0 ? 4 - (encoded_len % 4) : 0;

	str_copy = pmalloc(encoded_len + pad + 1);
	/* Set all with pad char, then replace with the original string */
	memset(str_copy, '=', encoded_len + pad);
	memcpy(str_copy, str_encoded, encoded_len);
	str_copy[encoded_len + pad] = '\0';

	for (i = 0; i < encoded_len; i++) {
		if (str_copy[i] == '-')
			str_copy[i] = '+';
		else if (str_copy[i] == '_')
			str_copy[i] = '/';
	}

	/* Now decode as regular base64 */
	success = base64_decode(str_copy, encoded_len + pad, result, result_len);

	free(str_copy);
	return success;
}

static char *
to_base64url(char const *base, size_t base_len)
{
	char const *pad;
	char *tmp;
	size_t len;
	int i;

	/* Remove padding, if present */
	len = base_len;
	do {
		pad = strchr(base, '=');
		if (pad == NULL)
			break;
		len = pad - base;
	} while(0);

	tmp = pmalloc(len + 1);
	memcpy(tmp, base, len);
	tmp[len] = '\0';

	for (i = 0; i < len; i++) {
		if (tmp[i] == '+')
			tmp[i] = '-';
		else if (tmp[i] == '/')
			tmp[i] = '_';
	}

	return tmp;
}

/*
 * Encode @in (with size @in_len) as base64url without trailing pad, and
 * allocate at @result.
 *
 * TODO (SLURM, RK) From the way this function keeps being called in pairs and
 * failing too late, it would appear the code should be caching the encoded
 * result during construction.
 */
bool
base64url_encode(unsigned char const *in, int in_len, char **result)
{
	BIO *b64, *mem;
	BUF_MEM *mem_buf;

	ERR_clear_error();

	mem = BIO_new(BIO_s_mem());
	if (mem == NULL)
		return false;

	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL) {
		BIO_free(mem);
		return false;
	}

	/*
	 * TODO (SLURM, RK) WHY IS THERE NO ERROR HANDLING HERE
	 * ARGGGGGGGGGGGGGGGGGGGGHHHHHHHHHHHHHHHHHHHHH
	 */
	mem = BIO_push(b64, mem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b64, in, in_len);
	BIO_flush(b64);
	BIO_get_mem_ptr(mem, &mem_buf);

	*result = to_base64url(mem_buf->data, mem_buf->length);

	BIO_free_all(b64);
	return true;
}
