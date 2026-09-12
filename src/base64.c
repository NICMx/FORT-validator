#include "base64.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

#include "alloc.h"
#include "hash.h"
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
	if (status < 0)
		goto cancel;

	*out_len = outl;

	status = EVP_DecodeFinal(ctx, result + outl, &outl);
	if (status != 1)
		goto cancel;

	EVP_ENCODE_CTX_free(ctx);
	*out = result;
	*out_len += outl;
	return true;

cancel:	EVP_ENCODE_CTX_free(ctx);
	return false;
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

	mem = BIO_push(b64, mem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	if (BIO_write(b64, in, in_len) < 0)
		goto fail;
	if (BIO_flush(b64) <= 0)
		goto fail;
	BIO_get_mem_ptr(mem, &mem_buf);

	*result = to_base64url(mem_buf->data, mem_buf->length);

	BIO_free_all(b64);
	return true;

fail:	BIO_free_all(b64);
	return false;
}

static void
prepare_buf(struct base64decode2file *b64, size_t data_len)
{
	size_t need_size;

	need_size = EVP_DECODE_LENGTH(data_len);

	if (!b64->buf) {
		b64->bufsize = need_size;
		b64->buf = pmalloc(need_size);
	} else if (need_size > b64->bufsize) {
		b64->bufsize = need_size;
		b64->buf = prealloc(b64->buf, need_size);
	}
}

/*
 * Steals ownership of @filename.
 * base64decode2file's must always be b64d2f_destroy()ed, even if this fails.
 */
int
b64d2f_init(struct base64decode2file *b64, char *filename)
{
	int error;

	if (b64->decoder == NULL) {
		b64->decoder = EVP_ENCODE_CTX_new();
		if (b64->decoder == NULL)
			enomem_panic();
	}
	EVP_DecodeInit(b64->decoder);
	b64->done = false;

	if (b64->hasher == NULL)
		b64->hasher = sha256_create();
	error = sha256_init(b64->hasher);
	if (error)
		goto fail;

	b64->file = fopen(filename, "w");
	if (!b64->file) {
		error = errno;
		pr_err("Cannot open %s for writing: %s",
		    filename, strerror(error));
		goto fail;
	}

	b64->filename = filename;
	return 0;

fail:	free(filename);
	return error;
}

static int
b64_write(struct base64decode2file *b64, int len)
{
	size_t buflen;

	if (len == 0)
		return 0;
	if (len < 0) {
		pr_err("Attempting to write a negative byte count: %d", len);
		return EINVAL;
	}

	buflen = len;
	if (fwrite(b64->buf, 1, buflen, b64->file) != buflen) {
		pr_err("Cannot write data to %s: Generic failure",
		    b64->filename);
		return EINVAL;
	}

	return sha256_update(b64->hasher, b64->buf, buflen);
}

int
b64d2f_write(struct base64decode2file *b64, char const *data, size_t len)
{
	int res;
	int outl;

	if (!b64->filename)
		return 0;

	if (b64->done) {
		pr_err("There's trailing text after the end of base64: '%.*s'",
		    (int)len, data);
		return EINVAL;
	}

	prepare_buf(b64, len);

	res = EVP_DecodeUpdate(b64->decoder, b64->buf, &outl,
	    (unsigned char const *)data, len);
	if (res < 0) {
		pr_err("Cannot decode base64: Generic error");
		return EINVAL;
	}
	if (res == 0)
		b64->done = true;

	return b64_write(b64, outl);
}

int
b64d2f_finish(struct base64decode2file *b64, unsigned char md[EVP_MAX_MD_SIZE])
{
	int outl;
	int error;

	if (!b64->filename)
		return 0;

	prepare_buf(b64, 66);

	if (EVP_DecodeFinal(b64->decoder, b64->buf, &outl) != 1)
		return pr_err("Cannot decode base64: Generic error");

	error = b64_write(b64, outl);
	if (error)
		return error;

	if (fclose(b64->file) == EOF)
		pr_wrn("Cannot close %s: %s", b64->filename, strerror(errno));
	b64->file = NULL;

	return sha256_finish(b64->hasher, md);
}

void
b64d2f_destroy(struct base64decode2file *b64)
{
	if (b64->decoder != NULL)
		EVP_ENCODE_CTX_free(b64->decoder);
	if (b64->buf != NULL)
		free(b64->buf);
	if (b64->filename != NULL)
		free(b64->filename);
	if (b64->file != NULL && fclose(b64->file) == EOF)
		pr_wrn("Cannot close %s: %s", b64->filename, strerror(errno));
	if (b64->hasher != NULL)
		sha256_destroy(b64->hasher);

	memset(b64, 0, sizeof(*b64));
}
