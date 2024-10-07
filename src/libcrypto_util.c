#include "libcrypto_util.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <time.h>

#include "alloc.h"
#include "asn1/asn1c/OBJECT_IDENTIFIER.h"
#include "extension.h"
#include "json_util.h"
#include "log.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define BIO_PR_TIME(bio, tm) ASN1_TIME_print_ex(bio, tm, ASN1_DTFLGS_ISO8601)
#else
#define BIO_PR_TIME(bio, tm) ASN1_TIME_print(bio, tm)
#endif

char *
asn1time2str(ASN1_TIME const *tm)
{
	BIO *bio;
	BUF_MEM *buf;
	char *res;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		enomem_panic();

	if (BIO_PR_TIME(bio, tm) <= 0)
		return NULL;

	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &buf);
	res = pstrndup(buf->data, buf->length);

	BIO_free_all(bio);
	return res;
}

/* Swallows @bio. */
static json_t *
bio2json(BIO *bio)
{
	BUF_MEM *buffer;
	json_t *json;

	json = (BIO_get_mem_ptr(bio, &buffer) > 0)
	    ? json_strn_new(buffer->data, buffer->length)
	    : NULL;

	BIO_free_all(bio);
	return json;
}

json_t *
oid2json(ASN1_OBJECT const *oid)
{
	char buf[OID_STR_MAXLEN];
	return (oid != NULL)
	     ? json_strn_new(buf, OBJ_obj2txt(buf, OID_STR_MAXLEN, oid, 0))
	     : json_null();
}

json_t *
asn1int2json(ASN1_INTEGER const *asn1int)
{
	BIGNUM *bignum;
	char *str;
	json_t *json;

	if (asn1int == NULL)
		return json_null();

	bignum = ASN1_INTEGER_to_BN(asn1int, NULL);
	str = BN_bn2hex(bignum);

	json = json_str_new(str);

	OPENSSL_free(str);
	BN_free(bignum);

	return json;
}

json_t *
asn1str2json(ASN1_STRING const *str)
{
	BIO *bio;
	int i;

	if (str == NULL)
		return json_null();

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		return NULL;

	for (i = 0; i < str->length; i++) {
		if (BIO_printf(bio, "%02x", str->data[i]) <= 0) {
			BIO_free_all(bio);
			return NULL;
		}
	}

	return bio2json(bio);
}

json_t *
asn1time2json(ASN1_TIME const *time)
{
	BIO *bio;

	if (time == NULL)
		return json_null();

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		return NULL;

	if (BIO_PR_TIME(bio, time) <= 0) {
		BIO_free_all(bio);
		return NULL;
	}

	return bio2json(bio);
}

json_t *
name2json(X509_NAME const *name)
{
	json_t *root, *rdnSeq;
	json_t *typeval, *child;
	X509_NAME_ENTRY *entry;
	int nid;
	const ASN1_STRING *data;
	int i;

	if (name == NULL)
		return json_null();

	root = json_obj_new();
	if (root == NULL)
		return NULL;
	if (json_object_add(root, "rdnSequence", rdnSeq = json_array_new()))
		goto fail;

	for (i = 0; i < X509_NAME_entry_count(name); i++) {
		if (json_array_add(rdnSeq, typeval = json_obj_new()))
			goto fail;

		entry = X509_NAME_get_entry(name, i);
		nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));
		data = X509_NAME_ENTRY_get_data(entry);

		child = json_str_new(OBJ_nid2ln(nid));
		if (json_object_add(typeval, "type", child))
			goto fail;

		child = json_strn_new((char *)data->data, data->length);
		if (json_object_add(typeval, "value", child))
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

json_t *
gn2json(GENERAL_NAME *gn)
{
	ASN1_IA5STRING *str;
	int type;

	if (gn == NULL)
		return json_null();

	str = GENERAL_NAME_get0_value(gn, &type);
	return (type == GEN_URI)
	    ? json_strn_new((char const *)str->data, str->length)
	    : json_str_new("<Not implemented for now>");
}

json_t *
gns2json(GENERAL_NAMES const *gns)
{
	json_t *parent;
	json_t *child;
	int n;

	if (gns == NULL)
		return json_null();

	parent = json_array_new();
	if (parent == NULL)
		return NULL;

	for (n = 0; n < sk_GENERAL_NAME_num(gns); n++) {
		child = gn2json(sk_GENERAL_NAME_value(gns, n));
		if (json_array_add(parent, child))
			goto fail;
	}

	return parent;

fail:	json_decref(parent);
	return NULL;
}

json_t *
pubkey2json(EVP_PKEY *pubkey)
{
	BIO *bio;

	if (pubkey == NULL)
		return NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		return NULL;
	if (PEM_write_bio_PUBKEY(bio, pubkey) <= 0) {
		BIO_free_all(bio);
		return NULL;
	}

	return bio2json(bio);
}

static json_t *
ext2json_known(struct extension_metadata const *meta, X509_EXTENSION *ext)
{
	void *decoded;
	json_t *json;

	decoded = X509V3_EXT_d2i(ext);
	if (decoded == NULL)
		return NULL;

	json = meta->to_json(decoded);

	meta->destructor(decoded);
	return json;
}

static json_t *
ext2json_unknown(X509_EXTENSION *ext)
{
	return asn1str2json(X509_EXTENSION_get_data(ext));
}

static json_t *
ext2json(X509_EXTENSION *ext)
{
	struct extension_metadata const **array, *meta;
	int nid;

	array = ext_metadatas();
	nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));

	for (meta = *array; meta != NULL; array++, meta = *array) {
		if (meta->nid == nid) {
			if (meta->to_json != NULL)
				return ext2json_known(meta, ext);
			else
				break;
		}
	}

	return ext2json_unknown(ext);
}

json_t *
exts2json(const STACK_OF(X509_EXTENSION) *exts)
{
	json_t *root;
	json_t *parent;
	json_t *child;
	X509_EXTENSION *ex;
	int i;

	if (sk_X509_EXTENSION_num(exts) <= 0)
		return json_null();

	root = json_array_new();
	if (root == NULL)
		return NULL;

	for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		if (json_array_add(root, parent = json_obj_new()))
			goto fail;

		ex = sk_X509_EXTENSION_value(exts, i);

		child = oid2json(X509_EXTENSION_get_object(ex));
		if (json_object_add(parent, "extnID", child))
			goto fail;
		child = json_boolean(X509_EXTENSION_get_critical(ex));
		if (json_object_add(parent, "critical", child))
			goto fail;
		child = ext2json(ex);
		if (json_object_add(parent, "extnValue", child))
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}
