#include "print_file.h"

#include <errno.h>
#include <stdlib.h>

#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"
#include "asn1/content_info.h"
#include "asn1/asn1c/Certificate.h"
#include "asn1/asn1c/CRL.h"
#include "data_structure/path_builder.h"
#include "rsync/rsync.h"
#include "types/bio_seq.h"
#include "types/uri.h"

#define HDRSIZE 32

static BIO *
__rsync2bio(char const *src, char const *dst)
{
	int error;

	error = rsync_download(src, dst, false);
	if (error) {
		pr_op_err("rysnc download failed: %s", strerror(abs(error)));
		return NULL;
	}

	return BIO_new_file(dst, "rb");
}

static BIO *
rsync2bio_tmpdir(char const *src)
{
#define TMPDIR "/tmp/fort-XXXXXX"

	struct path_builder pb;
	char buf[strlen(TMPDIR) + 1];
	char *tmpdir;
	BIO *result = NULL;
	int error;

	strcpy(buf, TMPDIR);
	tmpdir = mkdtemp(buf);
	if (tmpdir == NULL) {
		pr_op_err("Unable to create " TMPDIR ": %s", strerror(errno));
		return NULL;
	}

	pb_init(&pb);
	error = pb_append(&pb, tmpdir);
	if (error)
		goto end;
	error = pb_append(&pb, strrchr(src, '/') + 1);
	if (error)
		goto end;

	result = __rsync2bio(src, pb.string);

end:	pb_cleanup(&pb);
	return result;
}

static BIO *
rsync2bio_cache(char const *src)
{
	char const *tal;
	struct rpki_uri *uri;
	BIO *bio;
	int error;

	tal = strrchr(config_get_tal(), '/');
	tal = (tal != NULL) ? (tal + 1) : config_get_tal();
	uri = NULL;

	error = uri_create(&uri, tal, UT_RSYNC, false, NULL, src);
	if (error) {
		pr_op_err("Unparseable rsync URI: %s", strerror(abs(error)));
		return NULL;
	}

	bio = __rsync2bio(uri_get_global(uri), uri_get_local(uri));

	uri_refput(uri);
	return bio;
}

static BIO *
rsync2bio(char const *src)
{
	return (config_get_tal() && config_get_local_repository())
	     ? rsync2bio_cache(src)
	     : rsync2bio_tmpdir(src);
}

static BIO *
filename2bio(char const *filename)
{
	if (filename == NULL || strcmp(filename, "-") == 0)
		return BIO_new_fp(stdin, BIO_NOCLOSE);

	if (str_starts_with(filename, "rsync://"))
		return rsync2bio(filename);

	return BIO_new_file(filename, "rb");
}

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
	if (len_len <= 0)
		return NULL;
	cursor += len_len + len;
	return (cursor <= (buf + HDRSIZE)) ? cursor : NULL;
}

static int
guess_file_type(BIO **bio, unsigned char *hdrbuf)
{
	unsigned char *ptr;
	size_t consumed;

	if (config_get_file_type() != FT_UNK)
		return config_get_file_type();

	if (!BIO_read_ex(*bio, hdrbuf, HDRSIZE, &consumed))
		return op_crypto_err("Cannot guess file type; IO error.");

	*bio = BIO_new_seq(BIO_new_mem_buf(hdrbuf, consumed), *bio);
	if ((*bio) == NULL)
		return op_crypto_err("BIO_new_seq() returned NULL.");

	if (hdrbuf[0] != 0x30) {
		pr_op_debug("File doesn't start with a SEQUENCE.");
		return FT_UNK;
	}
	ptr = skip_sequence(hdrbuf, hdrbuf + 1);
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

	ptr = skip_sequence(hdrbuf, ptr + 1);
	if (ptr == NULL) {
		pr_op_debug("Cannot skip second sequence length.");
		return FT_UNK;
	}
	ptr = skip_integer(hdrbuf, ptr + 1);
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
bio2ci(BIO *bio)
{
#define BUFFER_SIZE 4096
	struct ContentInfo *ci = NULL;
	unsigned char buffer[BUFFER_SIZE];
	size_t consumed;
//	bool eof;
	asn_dec_rval_t res;

//	eof = false;
	do {
		if (!BIO_read_ex(bio, buffer, BUFFER_SIZE, &consumed)) {
			op_crypto_err("IO error.");
			goto fail;
		}

		res = ber_decode(&asn_DEF_ContentInfo, (void **)&ci,
				 buffer, consumed);
		pr_op_debug("Consumed: %zu", res.consumed);

		switch (res.code) {
		case RC_OK:
//			if (!buf->eof)
//				pr_op_warn("File has trailing bytes.");
			return ci;

		case RC_WMORE:
//			if (buf->eof) {
//				pr_op_err("File ended prematurely.");
//				return NULL;
//			}
			break;

		case RC_FAIL:
			pr_op_err("Unsuccessful parse.");
			goto fail;
		}
	} while (true);

fail:	ASN_STRUCT_FREE(asn_DEF_ContentInfo, ci);
	return NULL;
}

static json_t *
asn1c2json(BIO *bio)
{
	struct ContentInfo *ci;
	json_t *json;

	ci = bio2ci(bio);
	if (ci == NULL)
		return NULL;

	json = json_encode(&asn_DEF_ContentInfo, ci);

	ASN_STRUCT_FREE(asn_DEF_ContentInfo, ci);
	return json;
}

static int
__print_file(void)
{
	BIO *bio;
	unsigned char hdrbuf[HDRSIZE];
	json_t *json = NULL;
	int error;

	bio = filename2bio(config_get_payload());
	if (bio == NULL)
		return pr_op_err("BIO_new_*() returned NULL.");

	switch (guess_file_type(&bio, hdrbuf)) {
	case FT_UNK:
		BIO_free_all(bio);
		return pr_op_err("Unrecognized file type.");

	case FT_ROA:
	case FT_MFT:
	case FT_GBR:
		json = asn1c2json(bio);
		break;
	case FT_CER:
		json = Certificate_bio2json(bio);
		break;
	case FT_CRL:
		json = CRL_bio2json(bio);
		break;
	}

	BIO_free_all(bio);
	if (json == NULL)
		return pr_op_err("Unable to parse.");

	errno = 0;
	if (json_dumpf(json, stdout, JSON_INDENT(4)) < 0) {
		error = errno;
		if (error)
			pr_op_err("Error writing JSON to file: %s", strerror(error));
		else
			pr_op_err("Unknown error writing JSON to file.");

	} else {
		error = 0;
		printf("\n");
	}

	json_decref(json);
	return error;
}

int
print_file(void)
{
	int error;

	error = bioseq_setup();
	if (error)
		return error;

	error = __print_file();

	bioseq_teardown();
	return error;
}
