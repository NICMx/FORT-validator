#include "hash.h"

#include <openssl/evp.h>

#include "alloc.h"
#include "file.h"
#include "log.h"

/*
 * TODO (fine) Delete this structure (use md directly) once OpenSSL < 3 support
 * is dropped.
 */
struct hash_algorithm {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MD *md;
#else
	EVP_MD const *md;
#endif
	size_t size;
	char const *name;
};

/*
 * EVP_sha256() and EVP_sha1() are now mildly deprecated ("present for
 * compatibility with OpenSSL before version 3.0").
 *
 * This is because they want to encourage explicit fetching, but also because
 * they want us to stop hardcoding the algorithms in the code.
 *
 * But we're RFC-bound to use these algorithms, so we only want the explicit
 * fetching part. (Which is done during hash_setup().)
 */
static struct hash_algorithm sha1;
static struct hash_algorithm sha256;

int
hash_setup(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	sha1.md = EVP_MD_fetch(NULL, "SHA1", NULL);
	if (sha1.md == NULL)
		return pr_op_err("This version of libcrypto does not seem to support SHA1.");
	sha1.size = EVP_MD_get_size(sha1.md);
	sha1.name = EVP_MD_get0_name(sha1.md);

	sha256.md = EVP_MD_fetch(NULL, "SHA256", NULL);
	if (sha256.md == NULL) {
		EVP_MD_free(sha1.md);
		return pr_op_err("This version of libcrypto does not seem to support SHA256.");
	}
	sha256.size = EVP_MD_get_size(sha256.md);
	sha256.name = EVP_MD_get0_name(sha256.md);

#else
	sha1.md = EVP_get_digestbyname("sha1");
	if (sha1.md == NULL)
		return pr_op_err("This version of libcrypto does not seem to support SHA1.");
	sha1.size = EVP_MD_size(sha1.md);
	sha1.name = EVP_MD_name(sha1.md);

	sha256.md = EVP_get_digestbyname("sha256");
	if (sha256.md == NULL)
		return pr_op_err("This version of libcrypto does not seem to support SHA256.");
	sha256.size = EVP_MD_size(sha256.md);
	sha256.name = EVP_MD_name(sha256.md);

#endif

	return 0;
}

void
hash_teardown(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MD_free(sha256.md);
	EVP_MD_free(sha1.md);
#endif
}

struct hash_algorithm const *
hash_get_sha1(void)
{
	return &sha1;
}

struct hash_algorithm const *
hash_get_sha256(void)
{
	return &sha256;
}

int
hash_file(struct hash_algorithm const *algorithm, char const *filename,
    unsigned char *result, size_t *result_size)
{
	FILE *file;
	struct stat stat;
	unsigned char *buffer;
	size_t consumed;
	EVP_MD_CTX *ctx;
	unsigned int hash_size;
	int error;

	error = file_open(filename, &file, &stat);
	if (error)
		return error;

	buffer = pmalloc(stat.st_blksize);

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		enomem_panic();

	if (!EVP_DigestInit_ex(ctx, algorithm->md, NULL)) {
		error = val_crypto_err("EVP_DigestInit_ex() failed");
		goto end;
	}

	do {
		consumed = fread(buffer, 1, stat.st_blksize, file);
		error = ferror(file);
		if (error) {
			pr_val_err("File reading error. Error message (apparently): %s",
			   strerror(error));
			goto end;
		}

		if (!EVP_DigestUpdate(ctx, buffer, consumed)) {
			error = val_crypto_err("EVP_DigestUpdate() failed");
			goto end;
		}

	} while (!feof(file));

	if (!EVP_DigestFinal_ex(ctx, result, &hash_size)) {
		error = val_crypto_err("EVP_DigestFinal_ex() failed");
		goto end;
	}
	if (hash_size != algorithm->size) {
		error = pr_op_err("libcrypto returned a %s hash sized %u bytes.",
		    algorithm->name, hash_size);
	}

	if (result_size)
		*result_size = hash_size;

end:
	EVP_MD_CTX_free(ctx);
	free(buffer);
	file_close(file);
	return error;
}

int
hash_validate_file(struct hash_algorithm const *algorithm, char const *path,
    unsigned char const *expected, size_t expected_len)
{
	unsigned char actual[EVP_MAX_MD_SIZE];
	size_t actual_len;
	int error;

	pr_clutter("Validating file hash: %s", path);

	if (expected_len != hash_get_size(algorithm))
		return pr_val_err("%s string has bogus size: %zu",
		    hash_get_name(algorithm), expected_len);

	error = hash_file(algorithm, path, actual, &actual_len);
	if (error)
		return error;

	if (expected_len != actual_len)
		goto fail;
	if (memcmp(expected, actual, expected_len) != 0)
		goto fail;

	return 0;

fail:
	error = pr_val_err("File '%s' does not match its expected hash.", path);
#ifdef UNIT_TESTING
	size_t i;
	printf("Expected: ");
	for (i = 0; i < expected_len; i++)
		printf("%02x", expected[i]);
	printf("\nActual:   ");
	for (i = 0; i < actual_len; i++)
		printf("%02x", actual[i]);
	printf("\n");
#endif
	return error;
}

static int
hash_buffer(struct hash_algorithm const *algorithm,
    unsigned char const *content, size_t content_len, unsigned char *hash)
{
	EVP_MD_CTX *ctx;
	unsigned int actual_len;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		enomem_panic();

	if (!EVP_DigestInit_ex(ctx, algorithm->md, NULL) ||
	    !EVP_DigestUpdate(ctx, content, content_len) ||
	    !EVP_DigestFinal_ex(ctx, hash, &actual_len)) {
		EVP_MD_CTX_free(ctx);
		return val_crypto_err("Buffer hashing failed");
	}

	EVP_MD_CTX_free(ctx);

	if (actual_len != algorithm->size)
		pr_crit("libcrypto returned a %s hash sized %u bytes.",
		    algorithm->name, actual_len);

	return 0;
}

int
hash_validate(struct hash_algorithm const *algorithm, unsigned char const *data,
    size_t data_len, unsigned char const *expected, size_t expected_len)
{
	unsigned char actual[EVP_MAX_MD_SIZE];
	int error;

	error = hash_buffer(algorithm, data, data_len, actual);
	if (error)
		return error;

	if (expected_len != algorithm->size)
		return EINVAL;
	if (memcmp(expected, actual, expected_len) != 0)
		return EINVAL;

	return 0;
}

char const *
hash_get_name(struct hash_algorithm const *algorithm)
{
	return algorithm->name;
}

size_t
hash_get_size(struct hash_algorithm const *algorithm)
{
	return algorithm->size;
}
