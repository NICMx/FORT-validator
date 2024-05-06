#include "print_file.h"

#include <errno.h>
#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"
#include "asn1/content_info.h"
#include "asn1/asn1c/Certificate.h"
#include "asn1/asn1c/CRL.h"

#define HDRSIZE 32

static unsigned char *
skip_sequence(unsigned char *buf, unsigned char *cursor)
{
	ber_tlv_len_t len;
	ssize_t len_len;

	len_len = ber_fetch_length(1, cursor, HDRSIZE - (cursor - buf), &len);
	if (len_len <= 0)
		return NULL;
	cursor += len_len;
	return (cursor <= (buf + HDRSIZE)) ? cursor : NULL;
}

static unsigned char *
skip_integer(unsigned char *buf, unsigned char *cursor)
{
	ber_tlv_len_t len;
	ssize_t len_len;

	len_len = ber_fetch_length(0, cursor, HDRSIZE - (cursor - buf), &len);
	if (len_len <= 0) {
		pr_op_debug("aoe");
		return NULL;
	}
	cursor += len_len + len;
	return (cursor <= (buf + HDRSIZE)) ? cursor : NULL;
}

static int
guess_file_type(FILE *file)
{
	unsigned char buf[HDRSIZE];
	unsigned char *ptr;

	if (config_get_file_type() != FT_UNK)
		return config_get_file_type();

	if (fread(buf, 1, HDRSIZE, file) != HDRSIZE) {
		pr_op_debug("File is too small or generic IO error.");
		return FT_UNK;
	}
	rewind(file);

	if (buf[0] != 0x30) {
		pr_op_debug("File doesn't start with a SEQUENCE.");
		return FT_UNK;
	}
	ptr = skip_sequence(buf, buf + 1);
	if (ptr == NULL) {
		pr_op_debug("Cannot skip first sequence length.");
		return FT_UNK;
	}

	if (*ptr == 0x06) {
		pr_op_debug("SEQ containing OID.");
		return FT_ROA; /* Same parser for mfts and gbrs */
	}
	if (*ptr != 0x30) {
		pr_op_debug("SEQ containing unexpected: 0x%x", *ptr);
		return FT_UNK;
	}

	ptr = skip_sequence(buf, ptr + 1);
	if (ptr == NULL) {
		pr_op_debug("Cannot skip second sequence length.");
		return FT_UNK;
	}
	ptr = skip_integer(buf, ptr + 1);
	if (ptr == NULL) {
		pr_op_debug("Cannot skip version number.");
		return FT_UNK;
	}

	if (*ptr == 0x02) {
		pr_op_debug("SEQ containing SEQ containing (INT, INT).");
		return FT_CER;
	}
	if (*ptr == 0x30) {
		pr_op_debug("SEQ containing SEQ containing (INT, SEQ).");
		return FT_CRL;
	}

	pr_op_debug("SEQ containing SEQ containing unexpected: 0x%x", *ptr);
	return FT_UNK;
}

static struct ContentInfo *
file2ci(FILE *file)
{
#define BUFFER_SIZE 1024
	struct ContentInfo *ci = NULL;
	unsigned char buffer[BUFFER_SIZE];
	size_t consumed;
	bool eof;
	asn_dec_rval_t res;

	eof = false;
	do {
		consumed = fread(buffer, 1, BUFFER_SIZE, file);
		if (consumed < BUFFER_SIZE) {
			if (feof(file)) {
				eof = true;
			} else if (ferror(file)) {
				pr_op_err("ferror.");
				return NULL;
			} else {
				pr_op_err("?");
				return NULL;
			}
		}

		res = ber_decode(NULL, &asn_DEF_ContentInfo, (void **)&ci, buffer, consumed);
		pr_op_debug("Consumed: %zu", res.consumed);

		switch (res.code) {
		case RC_OK:
			if (!eof)
				pr_op_warn("File has trailing bytes.");
			return ci;

		case RC_WMORE:
			if (eof) {
				pr_op_err("File ended prematurely.");
				return NULL;
			}
			break;

		case RC_FAIL:
			pr_op_err("Unsuccessful parse.");
			return NULL;
		}
	} while (true);
}

static json_t *
asn1c2json(FILE *file)
{
	struct ContentInfo *ci;
	json_t *json;

	ci = file2ci(file);
	if (ci == NULL)
		return NULL;

	json = json_encode(&asn_DEF_ContentInfo, ci);

	ASN_STRUCT_FREE(asn_DEF_ContentInfo, ci);
	return json;
}

int
print_file(void)
{
	char const *filename = config_get_payload();
	FILE *file;
	json_t *json = NULL;
	int error = 0;

	if (filename == NULL || strcmp(filename, "-") == 0) {
		file = stdin;
	} else {
		file = fopen(filename, "rb");
		if (file == NULL)
			return pr_op_err("Cannot open file: %s", strerror(errno));
	}

	switch (guess_file_type(file)) {
	case FT_UNK:
		error = pr_op_err("Unrecognized file type.");
		break;
	case FT_ROA:
	case FT_MFT:
	case FT_GBR:
		json = asn1c2json(file);
		break;
	case FT_CER:
		json = Certificate_file2json(file);
		break;
	case FT_CRL:
		json = CRL_file2json(file);
		break;
	}

	if (file != stdin)
		fclose(file);
	if (error)
		return error;
	if (json == NULL)
		return pr_op_err("Unable to parse.");

	errno = 0;
	if (json_dumpf(json, stdout, JSON_INDENT(4)) < 0) {
		error = errno;
		if (error)
			pr_op_err("Error writing JSON to file: %s", strerror(error));
		else
			pr_op_err("Unknown error writing JSON to file.");
		goto end;
	}

	error = 0;
	printf("\n");
end:	json_decref(json);
	return error;
}
