#include "hash.h"

#include <errno.h>
#include <openssl/evp.h>
#include <sys/stat.h>

#include "log.h"

#define ALGORITHM "sha256"
static EVP_MD const *md;

int
hash_init(void)
{
	md = EVP_get_digestbyname(ALGORITHM);
	if (md == NULL) {
		printf("Unknown message digest %s\n", ALGORITHM);
		return -EINVAL;
	}

	return 0;
}

static int
hash_file(char *filename, unsigned char *result, unsigned int *result_len)
{
	FILE *file;
	struct stat stat;
	unsigned char *buffer;
	__blksize_t buffer_len;
	size_t consumed;
	EVP_MD_CTX *ctx;
	int error;

	file = fopen(filename, "rb");
	if (file == NULL)
		return pr_errno(errno, "Could not open file '%s'", filename);

	buffer_len = (fstat(fileno(file), &stat) == 0) ? stat.st_blksize : 1024;
	buffer = malloc(buffer_len);
	if (buffer == NULL) {
		pr_err("Out of memory.");
		error = -ENOMEM;
		goto end1;
	}

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		pr_err("Out of memory.");
		error = -ENOMEM;
		goto end2;
	}

	if (!EVP_DigestInit_ex(ctx, md, NULL)) {
		error = crypto_err("EVP_DigestInit_ex() failed");
		goto end3;
	}

	do {
		consumed = fread(buffer, 1, buffer_len, file);
		error = ferror(file);
		if (error) {
			pr_errno(error,
			    "File reading error. Error message (apparently)");
			goto end3;
		}

		if (!EVP_DigestUpdate(ctx, buffer, consumed)) {
			error = crypto_err("EVP_DigestUpdate() failed");
			goto end3;
		}

	} while (!feof(file));

	if (!EVP_DigestFinal_ex(ctx, result, result_len))
		error = crypto_err("EVP_DigestFinal_ex() failed");

end3:
	EVP_MD_CTX_free(ctx);
end2:
	free(buffer);
end1:
	if (fclose(file) == -1)
		pr_errno(errno, "fclose() failed");
	return error;
}

/**
 * Computes the hash of the file whose name is @filename, and compares it to
 * @expected (The "expected" hash). Returns 0 if no errors happened and the
 * hashes match.
 */
int
hash_validate(char *filename, BIT_STRING_t *expected)
{
	unsigned char actual[EVP_MAX_MD_SIZE];
	unsigned int actual_len;
	int error;

	if (expected->bits_unused != 0) {
		pr_err("Hash string has unused bits.");
		return -EINVAL;
	}

	error = hash_file(filename, actual, &actual_len);
	if (error)
		return error;

	if (expected->size != actual_len)
		goto mismatch;
	if (memcmp(expected->buf, actual, actual_len) != 0)
		goto mismatch;

	return 0;

mismatch:
	pr_err("File does not match its hash.");
	return -EINVAL;
}
