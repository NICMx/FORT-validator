#include "crypto/base64.h"

#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "alloc.h"

/*
 * Reference: openbsd/src/usr.bin/openssl/enc.c
 *
 * @in: The BIO that will stream the base64 encoded string you want to decode.
 * @out: Buffer where this function will write the decoded string.
 * @has_nl: Encoded string has newline char?
 * @out_len: Total allocated size of @out. It's supposed to be the result of
 *     EVP_DECODE_LENGTH(<size of the encoded string>).
 * @out_written: This function will write the actual number of decoded bytes
 *     here.
 *
 * Returns true on success, false on failure. If the caller wants to print
 * errors, do it with the crypto functions. If not, remember to clean
 * libcrypto's error queue somehow.
 *
 * TODO (fine) Callers always do a bunch of boilerplate; refactor.
 */
bool
base64_decode(BIO *in, unsigned char *out, bool has_nl, size_t out_len,
    size_t *out_written)
{
	BIO *b64;
	size_t offset = 0;
	int written = 0;
	bool success = false;

	/*
	 * BTW: The libcrypto API is perplexing.
	 * Peeking at the error stack is the only way I found to figure out
	 * whether some of the functions error'd.
	 * But since it's not documented that it's supposed to work this way,
	 * there's no guarantee that it will catch all errors.
	 * But it will have to do. It's better than nothing.
	 */

	/* Assume that the caller took care of handling any previous errors. */
	ERR_clear_error();

	/*
	 * BIO_f_base64() cannot fail because it's dead-simple by definition.
	 * BIO_new() can, and it will lead to NULL. But only *some* errors will
	 * populate the error stack.
	 */
	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL)
		return false;

	/*
	 * BIO_push() can technically fail through BIO_ctrl(), but it ignores
	 * the error. This will not cause it to revert the push, so we have to
	 * do it ourselves.
	 *
	 * BTW: I'm assigning the result of BIO_push() to @in (instead of @b64
	 * or, more logically, throwing it away) because the sample reference in
	 * enc.c does it that way.
	 * But the writer of enc.c probably overcomplicated things.
	 * It shouldn't make a difference. We don't need @in anymore; just
	 * assume both @b64 and @in now point to the same BIO, which is @b64.
	 */
	in = BIO_push(b64, in);

	/*
	 * Should we ignore this error? BIO_ctrl(BIO_CTRL_PUSH) performs some
	 * "internal, used to signify change" thing, whose importance is
	 * undefined due to BIO_ctrl()'s callback spaghetti.
	 * Let's be strict, I guess.
	 */
	if (ERR_peek_last_error() != 0)
		goto end;

	if (!has_nl)
		BIO_set_flags(in, BIO_FLAGS_BASE64_NO_NL); /* Cannot fail */

	do {
		/*
		 * Do not move this after BIO_read().
		 * BIO_read() can return negative, which does not necessarily
		 * imply error, and which ruins the counter.
		 */
		offset += written;
		written = BIO_read(in, out + offset, out_len - offset);
	} while (written > 0);

	/* BIO_read() can fail. It does not return status. */
	if (ERR_peek_last_error() != 0)
		goto end;

	*out_written = offset;
	success = true;

end:
	/*
	 * BIO_pop() can also fail due to BIO_ctrl(), but we will ignore this
	 * because whatever "signify change" crap happens, it can't possibly be
	 * damaging enough to prevent us from releasing b64. I hope.
	 */
	BIO_pop(b64);
	/* Returns 0 on failure, but that's only if b64 is NULL. Meaningless. */
	BIO_free(b64);

	return success;
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
	BIO *encoded; /* base64 encoded. */
	char *str_copy;
	size_t encoded_len, alloc_size, dec_len;
	int pad, i;

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
	encoded =  BIO_new_mem_buf(str_copy, -1);
	if (encoded == NULL)
		goto free_copy;

	alloc_size = EVP_DECODE_LENGTH(strlen(str_copy));
	*result = pzalloc(alloc_size + 1);

	if (!base64_decode(encoded, *result, false, alloc_size, &dec_len))
		goto free_all;

	if (dec_len == 0)
		goto free_all;

	*result_len = dec_len;

	free(str_copy);
	BIO_free(encoded);
	return true;

free_all:
	free(*result);
	BIO_free(encoded);
free_copy:
	free(str_copy);
	return false;
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
