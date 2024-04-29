#include "extension.h"

#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>
#include "cert_stack.h"
#include "common.h"
#include "libcrypto_util.h"
#include "log.h"
#include "nid.h"
#include "thread_var.h"
#include "crypto/hash.h"

static json_t *
unimplemented(void const *arg)
{
	return arg ? json_string("<Not implemented for now>") : json_null();
}

static json_t *
bc2json(void const *ext)
{
	BASIC_CONSTRAINTS const *bc = ext;
	json_t *root;

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "cA", json_boolean(bc->ca)) < 0)
		goto fail;
	if (json_object_set_new(root, "pathLenConstraint", asn1int2json(bc->pathlen)) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static void
bc_destroy(void *bc)
{
	BASIC_CONSTRAINTS_free(bc);
}

static const struct extension_metadata BC = {
	"Basic Constraints",
	NID_basic_constraints,
	true,
	bc2json,
	bc_destroy,
};

static json_t *
ski2json(void const *ext)
{
	return asn1str2json(ext);
}

static void
ski_destroy(void *ski)
{
	ASN1_OCTET_STRING_free(ski);
}

static const struct extension_metadata SKI = {
	"Subject Key Identifier",
	NID_subject_key_identifier,
	false,
	ski2json,
	ski_destroy,
};

static json_t *
aki2json(void const *ext)
{
	AUTHORITY_KEYID const *aki = ext;
	json_t *root;

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "keyIdentifier", asn1str2json(aki->keyid)) < 0)
		goto fail;
	if (json_object_set_new(root, "authorityCertIssuer", unimplemented(aki->issuer)) < 0)
		goto fail;
	if (json_object_set_new(root, "authorityCertSerialNumber", asn1int2json(aki->serial)) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static void
aki_destroy(void *aki)
{
	AUTHORITY_KEYID_free(aki);
}

static const struct extension_metadata AKI = {
	"Authority Key Identifier",
	NID_authority_key_identifier,
	false,
	aki2json,
	aki_destroy,
};

static json_t *
ku2json(void const *ext)
{
	ASN1_BIT_STRING const *ku = ext;
	unsigned char data[2];
	json_t *root;

	if (ku->length < 1 || 2 < ku->length)
		return NULL;
	memset(data, 0, sizeof(data));
	memcpy(data, ku->data, ku->length);

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "digitalSignature", json_boolean(ku->data[0] & 0x80u)) < 0)
		goto fail;
	if (json_object_set_new(root, "contentCommitment", json_boolean(ku->data[0] & 0x40u)) < 0)
		goto fail;
	if (json_object_set_new(root, "keyEncipherment", json_boolean(ku->data[0] & 0x20u)) < 0)
		goto fail;
	if (json_object_set_new(root, "dataEncipherment", json_boolean(ku->data[0] & 0x10u)) < 0)
		goto fail;
	if (json_object_set_new(root, "keyAgreement", json_boolean(ku->data[0] & 0x08u)) < 0)
		goto fail;
	if (json_object_set_new(root, "keyCertSign", json_boolean(ku->data[0] & 0x04u)) < 0)
		goto fail;
	if (json_object_set_new(root, "cRLSign", json_boolean(ku->data[0] & 0x02u)) < 0)
		goto fail;
	if (json_object_set_new(root, "encipherOnly", json_boolean(ku->data[0] & 0x01u)) < 0)
		goto fail;
	if (json_object_set_new(root, "decipherOnly", json_boolean(ku->data[1] & 0x80u)) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static void
ku_destroy(void *ku)
{
	ASN1_BIT_STRING_free(ku);
}

static const struct extension_metadata KU = {
	"Key Usage",
	NID_key_usage,
	true,
	ku2json,
	ku_destroy,
};

static json_t *
dpname2json(DIST_POINT_NAME const *dpn)
{
	if (dpn == NULL)
		return json_null();
	if (dpn->type) /* if relativename */
		return name2json(dpn->dpname);
	return gns2json(dpn->name.fullname);
}

static json_t *
cdp2json(void const *ext)
{
	STACK_OF(DIST_POINT) const *crldp = ext;
	json_t *root, *child;
	DIST_POINT *dp;
	int d;

	root = json_array();
	if (root == NULL)
		return NULL;

	for (d = 0; d < sk_DIST_POINT_num(crldp); d++) {
		dp = sk_DIST_POINT_value(crldp, 0);
		if (json_array_append_new(root, child = json_object()) < 0)
			goto fail;
		if (json_object_set_new(child, "distributionPoint", dpname2json(dp->distpoint)) < 0)
			goto fail;
		if (json_object_set_new(child, "reasons", unimplemented(dp->reasons)) < 0)
			goto fail;
		if (json_object_set_new(child, "cRLIssuer", gns2json(dp->CRLissuer)) < 0)
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

static void
cdp_destroy(void *crldp)
{
	sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
}

static const struct extension_metadata CDP = {
	"CRL Distribution Points",
	NID_crl_distribution_points,
	false,
	cdp2json,
	cdp_destroy,
};

static json_t *
aia2json(void const *ext)
{
	AUTHORITY_INFO_ACCESS const *ia = ext;
	ACCESS_DESCRIPTION *ad;
	json_t *root, *child;
	int i;

	root = json_array();
	if (root == NULL)
		return NULL;

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(ia, i);
		if (json_array_append_new(root, child = json_object()) < 0)
			goto fail;
		if (json_object_set_new(child, "accessMethod", oid2json(ad->method)) < 0)
			goto fail;
		if (json_object_set_new(child, "accessLocation", gn2json(ad->location)) < 0)
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

static void
aia_destroy(void *aia)
{
	AUTHORITY_INFO_ACCESS_free(aia);
}

static const struct extension_metadata AIA = {
	"Authority Information Access",
	NID_info_access,
	false,
	aia2json,
	aia_destroy,
};

static const struct extension_metadata SIA = {
	"Subject Information Access",
	NID_sinfo_access ,
	false,
	aia2json,
	aia_destroy,
};

static json_t *
pq2json(POLICYQUALINFO const *pqi)
{
	json_t *root;

	if (pqi == NULL)
		return json_null();

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "policyQualifierId", oid2json(pqi->pqualid)) < 0)
		goto fail;
	if (json_object_set_new(root, "qualifier", unimplemented(&pqi->d)) < 0)
		goto fail;

	return NULL;

fail:	json_decref(root);
	return NULL;
}

static json_t *
pqs2json(STACK_OF(POLICYQUALINFO) const *pqs)
{
	json_t *root;
	int i;

	if (pqs == NULL)
		return json_null();

	root = json_array();
	if (root == NULL)
		return NULL;

	for (i = 0; i < sk_POLICYQUALINFO_num(pqs); i++)
		if (json_array_append_new(root, pq2json(sk_POLICYQUALINFO_value(pqs, i))) < 0)
			goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
pi2json(POLICYINFO const *pi)
{
	json_t *root;

	if (pi == NULL)
		return json_null();

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "policyIdentifier", oid2json(pi->policyid)) < 0)
		goto fail;
	if (json_object_set_new(root, "policyQualifiers", pqs2json(pi->qualifiers)) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
cp2json(void const *ext)
{
	CERTIFICATEPOLICIES const *cp = ext;
	json_t *root;
	int i;

	root = json_array();
	if (root == NULL)
		return NULL;

	for (i = 0; i < sk_POLICYINFO_num(cp); i++)
		if (json_array_append_new(root, pi2json(sk_POLICYINFO_value(cp, i))) < 0)
			goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static void
cp_destroy(void *cp)
{
	CERTIFICATEPOLICIES_free(cp);
}

static const struct extension_metadata CP = {
	"Certificate Policies",
	NID_certificate_policies,
	true,
	cp2json,
	cp_destroy,
};

static json_t *
p2json(ASN1_BIT_STRING const *ap, int af)
{
	unsigned char bin[16];
	char str[INET6_ADDRSTRLEN];
	unsigned int length;
	json_t *root;

	if (ap == NULL)
		return json_null();

	memset(bin, 0, sizeof(bin));
	memcpy(bin, ap->data, ap->length);
	if (inet_ntop(af, bin, str, INET6_ADDRSTRLEN) == NULL)
		return NULL;

	length = 8 * ap->length;
	if (ap->flags & ASN1_STRING_FLAG_BITS_LEFT)
		length -= ap->flags & 7;

	root = json_object();
	if (root == NULL)
		return NULL;
	if (json_object_set_new(root, "address", json_string(str)) < 0)
		goto fail;
	if (json_object_set_new(root, "length", json_integer(length)) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
iaor2json(IPAddressOrRange const *iaor, int af)
{
	json_t *root;

	if (iaor == NULL)
		return json_null();

	switch (iaor->type) {
	case IPAddressOrRange_addressPrefix:
		return p2json(iaor->u.addressPrefix, af);
	case IPAddressOrRange_addressRange:
		return unimplemented(iaor->u.addressRange);
	}

	json_decref(root);
	return NULL;
}

static json_t *
iac2json(IPAddressChoice const *iac, int af)
{
	json_t *root;
	IPAddressOrRanges *iaor;
	int i;

	if (iac == NULL)
		return json_null();

	switch (iac->type) {
	case IPAddressChoice_inherit:
		return json_string("inherit");

	case IPAddressChoice_addressesOrRanges:
		iaor = iac->u.addressesOrRanges;
		if (iaor == NULL)
			return json_null();
		root = json_array();
		if (root == NULL)
			goto fail;
		for (i = 0; i < sk_IPAddressOrRange_num(iaor); i++)
			if (json_array_append_new(root, iaor2json(sk_IPAddressOrRange_value(iaor, i), af)) < 0)
				goto fail;
		return root;
	}

	return NULL;

fail:	json_decref(root);
	return NULL;
}

static json_t *
iaf2json(IPAddressFamily const *iaf)
{
	json_t *root;
	ASN1_OCTET_STRING *af;
	char const *family;
	int afid;

	if (iaf == NULL)
		return json_null();

	root = json_object();
	if (root == NULL)
		return NULL;

	af = iaf->addressFamily;
	if (af->length != 2)
		goto fail;

	if (af->data[0] == 0 && af->data[1] == 1) {
		family = "IPv4";
		afid = AF_INET;
	} else if (af->data[0] == 0 && af->data[1] == 2) {
		family = "IPv6";
		afid = AF_INET6;
	} else {
		goto fail;
	}

	if (json_object_set_new(root, "addressFamily", json_string(family)) < 0)
		goto fail;
	if (json_object_set_new(root, "ipAddressChoice", iac2json(iaf->ipAddressChoice, afid)) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
ir2json(void const *ext)
{
	STACK_OF(IPAddressFamily) const *iafs = ext;
	json_t *root;
	int i;

	root = json_array();
	if (root == NULL)
		return NULL;

	for (i = 0; i < sk_IPAddressFamily_num(iafs); i++)
		if (json_array_append_new(root, iaf2json(sk_IPAddressFamily_value(iafs, i))) < 0)
			goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static void
ir_destroy(void *ir)
{
	sk_IPAddressFamily_pop_free(ir, IPAddressFamily_free);
}

static const struct extension_metadata IR = {
	"IP Resources",
	NID_sbgp_ipAddrBlock,
	true,
	ir2json,
	ir_destroy,
};

static json_t *
asr2json(ASRange const *range)
{
	json_t *root;

	if (range == NULL)
		return json_null();

	root = json_object();
	if (root == NULL)
		return NULL;
	if (json_object_set_new(root, "min", asn1int2json(range->min)) < 0)
		goto fail;
	if (json_object_set_new(root, "max", asn1int2json(range->max)) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
aor2json(ASIdOrRange const *aor)
{
	json_t *root;

	if (aor == NULL)
		return json_null();

	switch (aor->type) {
	case ASIdOrRange_id:
		return asn1int2json(aor->u.id);
	case ASIdOrRange_range:
		return asr2json(aor->u.range);
	}

	json_decref(root);
	return NULL;
}

static json_t *
asidc2json(ASIdentifierChoice const *asidc)
{
	json_t *root;
	ASIdOrRanges *iaor;
	int i;

	if (asidc == NULL)
		return json_null();

	switch (asidc->type) {
	case ASIdentifierChoice_inherit:
		return json_string("inherit");

	case ASIdentifierChoice_asIdsOrRanges:
		iaor = asidc->u.asIdsOrRanges;
		if (iaor == NULL)
			return json_null();
		root = json_array();
		if (root == NULL)
			goto fail;
		for (i = 0; i < sk_ASIdOrRange_num(iaor); i++)
			if (json_array_append_new(root, aor2json(sk_ASIdOrRange_value(iaor, i))) < 0)
				goto fail;
		return root;
	}

	return NULL;

fail:	json_decref(root);
	return NULL;
}

static json_t *
ar2json(void const *ext)
{
	ASIdentifiers const *asid = ext;
	json_t *root;

	if (asid == NULL)
		return json_null();

	root = json_object();
	if (root == NULL)
		return NULL;
	if (json_object_set_new(root, "asnum", asidc2json(asid->asnum)) < 0)
		goto fail;
	if (json_object_set_new(root, "rdi", asidc2json(asid->rdi)) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static void
ar_destroy(void *ar)
{
	ASIdentifiers_free(ar);
}

static const struct extension_metadata AR = {
	"AS Resources",
	NID_sbgp_autonomousSysNum,
	true,
	ar2json,
	ar_destroy,
};

static struct extension_metadata IR2 = {
	"Amended IP Resources",
	-1,
	true,
	ir2json,
	ir_destroy,
};

static struct extension_metadata AR2 = {
	"Amended AS Resources",
	-1,
	true,
	ar2json,
	ir_destroy,
};

static json_t *
cn2json(void const *ext)
{
	return asn1int2json(ext);
}

static void
cn_destroy(void *cn)
{
	ASN1_INTEGER_free(cn);
}

static const struct extension_metadata CN = {
	"CRL Number",
	NID_crl_number,
	false,
	cn2json,
	cn_destroy,
};

static json_t *
eku2json(void const *ext)
{
	EXTENDED_KEY_USAGE const *eku = ext;
	json_t *root;
	int i;

	root = json_array();
	if (root == NULL)
		return root;

	for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++)
		if (json_array_append_new(root, oid2json(sk_ASN1_OBJECT_value(eku, i))) < 0)
			goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static void
eku_destroy(void *eku)
{
	EXTENDED_KEY_USAGE_free(eku);
}

static const struct extension_metadata EKU = {
	"Extended Key Usage",
	NID_ext_key_usage,
	false,
	eku2json,
	eku_destroy,
};

int extension_init(void)
{
	IR2.nid = nid_ipAddrBlocksv2();
	AR2.nid = nid_autonomousSysIdsv2();
	return 0;
}

struct extension_metadata const *ext_bc(void)	{ return &BC; }
struct extension_metadata const *ext_ski(void)	{ return &SKI; }
struct extension_metadata const *ext_aki(void)	{ return &AKI; }
struct extension_metadata const *ext_ku(void)	{ return &KU; }
struct extension_metadata const *ext_cdp(void)	{ return &CDP; }
struct extension_metadata const *ext_aia(void)	{ return &AIA; }
struct extension_metadata const *ext_sia(void)	{ return &SIA; }
struct extension_metadata const *ext_cp(void)	{ return &CP; }
struct extension_metadata const *ext_ir(void)	{ return &IR; }
struct extension_metadata const *ext_ar(void)	{ return &AR; }
struct extension_metadata const *ext_ir2(void)	{ return &IR2; }
struct extension_metadata const *ext_ar2(void)	{ return &AR2; }
struct extension_metadata const *ext_cn(void)	{ return &CN; }
struct extension_metadata const *ext_eku(void)	{ return &EKU; }

struct extension_metadata const **
ext_metadatas(void)
{
	static struct extension_metadata const *array[] = {
		&BC,  &SKI, &AKI, &KU,
		&CDP, &AIA, &SIA, &CP,
		&IR,  &AR,  &IR2, &AR2,
		&CN,  &EKU, NULL
	};
	return array;
}

static int
handle_extension(struct extension_handler *handlers, X509_EXTENSION *ext)
{
	struct extension_handler *handler;
	int nid;

	nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));

	for (handler = handlers; handler->meta != NULL; handler++) {
		if (handler->meta->nid == nid) {
			if (handler->found)
				goto dupe;
			handler->found = true;

			if (handler->meta->critical) {
				if (!X509_EXTENSION_get_critical(ext))
					goto not_critical;
			} else {
				if (X509_EXTENSION_get_critical(ext))
					goto critical;
			}

			return handler->cb(ext, handler->arg);
		}
	}

	if (!X509_EXTENSION_get_critical(ext))
		return 0; /* Unknown and not critical; ignore it. */

	/*
	 * TODO (next iteration?) print the NID as string.
	 * Also "unknown" is misleading. I think it's only "unknown" if the NID
	 * is -1 or something like that.
	 */
	return pr_val_err("Certificate has unknown extension. (Extension NID: %d)",
	    nid);
dupe:
	return pr_val_err("Certificate has more than one '%s' extension.",
	    handler->meta->name);
not_critical:
	return pr_val_err("Extension '%s' is supposed to be marked critical.",
	    handler->meta->name);
critical:
	return pr_val_err("Extension '%s' is not supposed to be marked critical.",
	    handler->meta->name);
}

int
handle_extensions(struct extension_handler *handlers,
    STACK_OF(X509_EXTENSION) const *extensions)
{
	struct extension_handler *handler;
	int e;
	int error;

	for (e = 0; e < sk_X509_EXTENSION_num(extensions); e++) {
		error = handle_extension(handlers,
		    sk_X509_EXTENSION_value(extensions, e));
		if (error)
			return error;
	}

	for (handler = handlers; handler->meta != NULL; handler++) {
		if (handler->mandatory && !handler->found)
			return pr_val_err("Certificate is missing the '%s' extension.",
			    handler->meta->name);
	}

	return 0;
}

int
cannot_decode(struct extension_metadata const *meta)
{
	return pr_val_err("Extension '%s' seems to be malformed. Cannot decode.",
	    meta->name);
}

/**
 * Returns 0 if the identifier (ie. SHA-1 hash) of @cert's public key is @hash.
 * Otherwise returns error code.
 */
int
validate_public_key_hash(X509 *cert, ASN1_OCTET_STRING *hash)
{
	X509_PUBKEY *pubkey;
	const unsigned char *spk;
	int spk_len;
	int ok;
	int error;

	/*
	 * I really can't tell if this validation needs to be performed.
	 * Probably not.
	 *
	 * "Applications are not required to verify that key identifiers match
	 * when performing certification path validation."
	 * (rfc5280#section-4.2.1.2)
	 *
	 * From its context, my reading is that the quote refers to the
	 * "parent's SKI must equal the children's AKI" requirement, not the
	 * "child's SKI must equal the SHA-1 of its own's SPK" requirement. So
	 * I think that we're only supposed to check the SHA-1. Or nothing at
	 * all, because we only care about the keys, not their identifiers.
	 *
	 * But the two requirements actually have a lot in common:
	 *
	 * The quote is from 5280, not 6487. 6487 chooses to enforce the SKI's
	 * "SHA-1 as identifier" option, even for the AKI. And if I'm validating
	 * the AKI's SHA-1, then I'm also indirectly checking the children vs
	 * parent relationship.
	 *
	 * Also, what's with using a hash as identifier? That's an accident
	 * waiting to happen...
	 *
	 * Bottom line, I don't know. But better be safe than sorry, so here's
	 * the validation.
	 *
	 * I feel like I'm losing so much performance because the RFCs are so
	 * wishy-washy about what is our realm and what is not.
	 */

	/* Get the SPK (ask libcrypto) */
	pubkey = X509_get_X509_PUBKEY(cert);
	if (pubkey == NULL)
		return val_crypto_err("X509_get_X509_PUBKEY() returned NULL");

	ok = X509_PUBKEY_get0_param(NULL, &spk, &spk_len, NULL, pubkey);
	if (!ok)
		return val_crypto_err("X509_PUBKEY_get0_param() returned %d", ok);

	/* Hash the SPK, compare SPK hash with the SKI */
	if (hash->length < 0 || SIZE_MAX < hash->length) {
		return pr_val_err("%s length (%d) is out of bounds. (0-%zu)",
		    ext_ski()->name, hash->length, SIZE_MAX);
	}
	if (spk_len < 0 || SIZE_MAX < spk_len) {
		return pr_val_err("Subject Public Key length (%d) is out of bounds. (0-%zu)",
		    spk_len, SIZE_MAX);
	}

	error = hash_validate("sha1", hash->data, hash->length, spk, spk_len);
	if (error) {
		pr_val_err("The Subject Public Key's hash does not match the %s.",
		    ext_ski()->name);
	}

	return error;
}

int
handle_aki(X509_EXTENSION *ext, void *arg)
{
	AUTHORITY_KEYID *aki;
	struct validation *state;
	X509 *parent;
	int error;

	aki = X509V3_EXT_d2i(ext);
	if (aki == NULL)
		return cannot_decode(ext_aki());

	if (aki->issuer != NULL) {
		error = pr_val_err("%s extension contains an authorityCertIssuer.",
		    ext_aki()->name);
		goto end;
	}
	if (aki->serial != NULL) {
		error = pr_val_err("%s extension contains an authorityCertSerialNumber.",
		    ext_aki()->name);
		goto end;
	}

	state = state_retrieve();
	parent = x509stack_peek(validation_certstack(state));
	if (parent == NULL) {
		error = pr_val_err("Certificate has no parent.");
		goto end;
	}

	error = validate_public_key_hash(parent, aki->keyid);

end:
	AUTHORITY_KEYID_free(aki);
	return error;
}
