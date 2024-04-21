#include "asn1/asn1c/Certificate.h"

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "alloc.h"

/* Swallows @bio. */
static json_t *
bio2json(BIO *bio)
{
	BUF_MEM *buffer;
	json_t *json;

	json = (BIO_get_mem_ptr(bio, &buffer) > 0)
	    ? json_stringn(buffer->data, buffer->length)
	    : NULL;

	BIO_free_all(bio);
	return json;
}

/* Swallows @bio. */
static char *
bio2str(BIO *bio)
{
	BUF_MEM *buffer;
	char *str;

	str = (BIO_get_mem_ptr(bio, &buffer) > 0)
	    ? pstrndup(buffer->data, buffer->length)
	    : NULL;

	BIO_free_all(bio);
	return str;
}

static json_t *
asn1int2json(ASN1_INTEGER const *asn1int)
{
	BIGNUM *bignum;
	char *str;
	json_t *json;

	if (asn1int == NULL)
		return NULL;

	bignum = ASN1_INTEGER_to_BN(asn1int, NULL);
	str = BN_bn2hex(bignum);

	json = json_string(str);

	OPENSSL_free(str);
	BN_free(bignum);

	return json;
}

static json_t *
name2json(X509_NAME const *name)
{
	json_t *root;
	json_t *child;
	int i;

	root = json_object();
	if (root == NULL)
		return NULL;

	for (i = 0; i < X509_NAME_entry_count(name); i++) {
		X509_NAME_ENTRY *entry;
		int nid;
		const ASN1_STRING *data;

		entry = X509_NAME_get_entry(name, i);
		nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));

		data = X509_NAME_ENTRY_get_data(entry);
		if (data == NULL)
			goto fail;
		child = json_stringn((char *)data->data, data->length);

		if (json_object_set_new(root, OBJ_nid2ln(nid), child) < 0)
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
asn1time2json(ASN1_TIME const *time)
{
	BIO *bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		return NULL;

	if (!ASN1_TIME_print_ex(bio, time, ASN1_DTFLGS_ISO8601)) {
		BIO_free_all(bio);
		return NULL;
	}

	return bio2json(bio);
}

static json_t *
validity2json(X509 *x)
{
	json_t *root;

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "notBefore", asn1time2json(X509_get0_notBefore(x))) < 0)
		goto fail;
	if (json_object_set_new(root, "notAfter", asn1time2json(X509_get0_notAfter(x))) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
pk2json(X509 const *x)
{
	json_t *root;
	ASN1_OBJECT *xpoid;
	EVP_PKEY *pkey;
	BIO *bio;

	root = json_object();
	if (root == NULL)
		return NULL;

	/* algorithm */
	if (!X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, X509_get_X509_PUBKEY(x)))
		goto fail;
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		goto fail;
	if (i2a_ASN1_OBJECT(bio, xpoid) <= 0) {
		BIO_free_all(bio);
		goto fail;
	}
	if (json_object_set_new(root, "algorithm", bio2json(bio)))
		goto fail;

	/* Actual pk */
	pkey = X509_get0_pubkey(x);
	if (pkey == NULL)
		goto fail;
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		goto fail;
	if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) {
		BIO_free_all(bio);
		goto fail;
	}
	if (json_object_set_new(root, "subjectPublicKey", bio2json(bio)))
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
bitstr2json(ASN1_BIT_STRING const *bitstr)
{
	BIO *bio;
	unsigned char *data;
	int length;
	int i;

	if (bitstr == NULL)
		return json_null();

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		return NULL;

	data = bitstr->data;
	length = bitstr->length;

	for (i = 0; i < length; i++) {
		if (BIO_printf(bio, "%02x", data[i]) <= 0) {
			BIO_free_all(bio);
			return NULL;
		}
	}

	return bio2json(bio);
}

static json_t *
iuid2json(X509 const *x)
{
	const ASN1_BIT_STRING *iuid;
	X509_get0_uids(x, &iuid, NULL);
	return bitstr2json(iuid);
}

static json_t *
suid2json(X509 const *x)
{
	const ASN1_BIT_STRING *suid;
	X509_get0_uids(x, NULL, &suid);
	return bitstr2json(suid);
}

static json_t *
exts2json(const STACK_OF(X509_EXTENSION) *exts)
{
	json_t *root;
	BIO *bio;
	int i;

	if (sk_X509_EXTENSION_num(exts) <= 0)
		return json_null();

	root = json_object();
	if (root == NULL)
		return NULL;

	for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		json_t *node;
		X509_EXTENSION *ex;

		ex = sk_X509_EXTENSION_value(exts, i);

		/* Get the extension name */
		bio = BIO_new(BIO_s_mem());
		if (bio == NULL)
			goto fail;
		if (i2a_ASN1_OBJECT(bio, X509_EXTENSION_get_object(ex)) <= 0) {
			BIO_free_all(bio);
			goto fail;
		}

		/* Create node, add to parent */
		node = json_object();
		if (node == NULL) {
			BIO_free_all(bio);
			goto fail;
		}
		if (json_object_set_new(root, bio2str(bio), node) < 0)
			goto fail;

		/* Child 1: Critical */
		if (json_object_set_new(node, "critical", X509_EXTENSION_get_critical(ex) ? json_true() : json_false()) < 0)
			goto fail;

		/* Child 2: Value */
		bio = BIO_new(BIO_s_mem());
		if (bio == NULL)
			goto fail;
		/* TODO Those flags are kinda interesting */
		if (!X509V3_EXT_print(bio, ex, 0, 0)) {
			BIO_free_all(bio);
			goto fail;
		}
		if (json_object_set_new(node, "value", bio2json(bio)) < 0)
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
tbsCert2json(X509 *x)
{
	json_t *tbsCert;

	tbsCert = json_object();
	if (tbsCert == NULL)
		return NULL;

	if (json_object_set_new(tbsCert, "version", json_integer(X509_get_version(x))) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "serialNumber", asn1int2json(X509_get0_serialNumber(x))) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "signature", json_string(OBJ_nid2ln(X509_get_signature_nid(x)))) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "issuer", name2json(X509_get_issuer_name(x))) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "validity", validity2json(x)) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "subject", name2json(X509_get_subject_name(x))) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "subjectPublicKeyInfo", pk2json(x)) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "issuerUniqueID", iuid2json(x)) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "subjectUniqueID", suid2json(x)) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "extensions", exts2json(X509_get0_extensions(x))) < 0)
		goto fail;

	return tbsCert;

fail:
	json_decref(tbsCert);
	return NULL;
}

static json_t *
sigAlgorithm2json(X509 *cert)
{
	const X509_ALGOR *palg;
	const ASN1_OBJECT *paobj;

	X509_get0_signature(NULL, &palg, cert);
	X509_ALGOR_get0(&paobj, NULL, NULL, palg);

	return json_string(OBJ_nid2ln(OBJ_obj2nid(paobj)));
}

static json_t *
sigValue2json(X509 *cert)
{
	const ASN1_BIT_STRING *signature;
	X509_get0_signature(&signature, NULL, cert);
	return bitstr2json(signature);
}

static json_t *
x509_to_json(X509 *x)
{
	json_t *root;

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "tbsCertificate", tbsCert2json(x)) < 0)
		goto fail;
	if (json_object_set_new(root, "signatureAlgorithm", sigAlgorithm2json(x)) < 0)
		goto fail;
	if (json_object_set_new(root, "signatureValue", sigValue2json(x)) < 0)
		goto fail;

	return root;

fail:
	json_decref(root);
	return NULL;
}

json_t *
Certificate_encode_json(ANY_t *ber)
{
	const unsigned char *tmp;
	X509 *cert;

	/*
	 * "If the call is successful *in is incremented to the byte following
	 * the parsed data."
	 * (https://www.openssl.org/docs/man1.0.2/crypto/d2i_X509_fp.html)
	 * We don't want @ber->buf modified, so use a dummy pointer.
	 */
	tmp = (const unsigned char *) ber->buf;

	cert = d2i_X509(NULL, &tmp, ber->size);
	if (cert == NULL)
		return NULL;

	json_t *root = x509_to_json(cert);
	if (root == NULL)
		goto fail;

	X509_free(cert);
	return root;

fail:	json_decref(root);
	X509_free(cert);
	return NULL;
}
