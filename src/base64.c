#include "base64.h"

#include <openssl/err.h>
#include <openssl/evp.h>

/**
 * Converts error from libcrypto representation to this project's
 * representation.
 */
static int
error_ul2i(unsigned long error)
{
	/* I'm assuming int has at least 32 bits. Don't mess with the sign. */
	int interror = error & 0x7FFFFFFFul;
	return interror ? interror : -EINVAL;
}

/*
 * Reference: openbsd/src/usr.bin/openssl/enc.c
 *
 * @in: The BIO that will stream the base64 encoded string you want to decode.
 * @out: Buffer where this function will write the decoded string.
 * @out_len: Total allocated size of @out. It's supposed to be the result of
 *     EVP_DECODE_LENGTH(<size of the encoded string>).
 * @out_written: This function will write the actual number of decoded bytes
 *     here.
 *
 * Returns error status. (Nonzero = error code, zero = success)
 *
 * If this returns error, do visit ERR_print_errors(), but also print an
 * additional error message anyway. Functions such as BIO_new() don't always
 * register a libcrypto stack error.
 */
int
base64_decode(BIO *in, unsigned char *out, size_t out_len, size_t *out_written)
{
	BIO *b64;
	size_t offset = 0;
	int written = 0;
	unsigned long error;

	/*
	 * BTW: The libcrypto API was clearly designed by fucking idiots.
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
	if (b64 == NULL) {
		error = ERR_peek_last_error();
		return error ? error_ul2i(error) : -ENOMEM;
	}

	/* TODO would changing this flag simplify file reading? */
	/* BIO_set_flags() cannot fail; it's dead-simple by definition. */
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	/*
	 * BIO_push() can technically fail through BIO_ctrl(), but it ignores
	 * the error. This will not cause it to revert the push, so we have to
	 * do it ourselves.
	 * Should we ignore this error? BIO_ctrl(BIO_CTRL_PUSH) performs some
	 * "internal, used to signify change" thing, whose importance is
	 * undefined due to BIO_ctrl()'s callback spaghetti.
	 * I'm not risking it.
	 */
	in = BIO_push(b64, in);
	error = ERR_peek_last_error();
	if (error)
		goto end;

	do {
		/*
		 * Do not move this after BIO_read().
		 * BIO_read() can return negative, which does not necessarily
		 * imply error, and which ruins the counter.
		 */
		offset += written;
		/*
		 * According to the documentation, the first argument should
		 * be b64, not in.
		 * But this is how it's written in enc.c.
		 * It doesn't seem to make a difference either way.
		 */
		written = BIO_read(in, out + offset, out_len - offset);
	} while (written > 0);

	/* BIO_read() can fail. It does not return status. */
	error = ERR_peek_last_error();
	*out_written = offset;

end:
	/*
	 * BIO_pop() can also fail due to BIO_ctrl(), but we will ignore this
	 * because whatever "signify change" crap happens, it can't possibly be
	 * damaging enough to prevent us from releasing b64. I hope.
	 */
	BIO_pop(b64);
	/* Returns 0 on failure, but that's only if b64 is NULL. Meaningless. */
	BIO_free(b64);

	return error ? error_ul2i(error) : 0;
}
