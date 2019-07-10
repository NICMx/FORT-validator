#include "extension.h"

#include <errno.h>
#include "common.h"
#include "log.h"
#include "nid.h"
#include "thread_var.h"
#include "crypto/hash.h"

static struct extension_metadata IR2 = {
	"Amended IP Resources",
	-1,
	true,
};

static struct extension_metadata AR2 = {
	"Amended AS Resources",
	-1,
	true,
};

int extension_init(void)
{
	IR2.nid = nid_ipAddrBlocksv2();
	AR2.nid = nid_autonomousSysIdsv2();
	return 0;
}

struct extension_metadata const *ext_bc(void)
{
	static const struct extension_metadata BC = {
		"Basic Constraints",
		NID_basic_constraints,
		true,
	};
	return &BC;
}

struct extension_metadata const *ext_ski(void)
{
	static const struct extension_metadata SKI = {
		"Subject Key Identifier",
		NID_subject_key_identifier,
		false,
	};
	return &SKI;
}

struct extension_metadata const *ext_aki(void)
{
	static const struct extension_metadata AKI = {
		"Authority Key Identifier",
		NID_authority_key_identifier,
		false,
	};
	return &AKI;
}

struct extension_metadata const *ext_ku(void)
{
	static const struct extension_metadata KU = {
		"Key Usage",
		NID_key_usage,
		true,
	};
	return &KU;
}

struct extension_metadata const *ext_cdp(void)
{
	static const struct extension_metadata CDP = {
		"CRL Distribution Points",
		NID_crl_distribution_points,
		false,
	};
	return &CDP;
}

struct extension_metadata const *ext_aia(void)
{
	static const struct extension_metadata AIA = {
		"Authority Information Access",
		NID_info_access,
		false,
	};
	return &AIA;
}

struct extension_metadata const *ext_sia(void)
{
	static const struct extension_metadata SIA = {
		"Subject Information Access",
		NID_sinfo_access ,
		false,
	};
	return &SIA;
}

struct extension_metadata const *ext_cp(void)
{
	static const struct extension_metadata CP = {
		"Certificate Policies",
		NID_certificate_policies,
		true,
	};
	return &CP;
}

struct extension_metadata const *ext_ir(void)
{
	static const struct extension_metadata IR = {
		"IP Resources",
		NID_sbgp_ipAddrBlock,
		true,
	};
	return &IR;
}

struct extension_metadata const *ext_ar(void)
{
	static const struct extension_metadata AR = {
		"AS Resources",
		NID_sbgp_autonomousSysNum,
		true,
	};
	return &AR;
}

struct extension_metadata const *ext_ir2(void)
{
	return &IR2;
}

struct extension_metadata const *ext_ar2(void)
{
	return &AR2;
}

struct extension_metadata const *ext_cn(void)
{
	static const struct extension_metadata CN = {
		"CRL Number",
		NID_crl_number,
		false,
	};
	return &CN;
}

struct extension_metadata const *ext_eku(void)
{
	static const struct extension_metadata EKU = {
		"Extended Key Usage",
		NID_ext_key_usage,
		false,
	};
	return &EKU;
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
	return pr_err("Certificate has unknown extension. (Extension NID: %d)",
	    nid);
dupe:
	return pr_err("Certificate has more than one '%s' extension.",
	    handler->meta->name);
not_critical:
	return pr_err("Extension '%s' is supposed to be marked critical.",
	    handler->meta->name);
critical:
	return pr_err("Extension '%s' is not supposed to be marked critical.",
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
			return pr_err("Certificate is missing the '%s' extension.",
			    handler->meta->name);
	}

	return 0;
}

int
cannot_decode(struct extension_metadata const *meta)
{
	return pr_err("Extension '%s' seems to be malformed. Cannot decode.",
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
	 * Shit. I feel like I'm losing so much performance because the RFCs
	 * are so wishy-washy about what is our realm and what is not.
	 */

	/* Get the SPK (ask libcrypto) */
	pubkey = X509_get_X509_PUBKEY(cert);
	if (pubkey == NULL)
		return crypto_err("X509_get_X509_PUBKEY() returned NULL");

	ok = X509_PUBKEY_get0_param(NULL, &spk, &spk_len, NULL, pubkey);
	if (!ok)
		return crypto_err("X509_PUBKEY_get0_param() returned %d", ok);

	/* Hash the SPK, compare SPK hash with the SKI */
	if (hash->length < 0 || SIZE_MAX < hash->length) {
		return pr_err("%s length (%d) is out of bounds. (0-%zu)",
		    ext_ski()->name, hash->length, SIZE_MAX);
	}
	if (spk_len < 0 || SIZE_MAX < spk_len) {
		return pr_err("Subject Public Key length (%d) is out of bounds. (0-%zu)",
		    spk_len, SIZE_MAX);
	}

	error = hash_validate("sha1", hash->data, hash->length, spk, spk_len);
	if (error) {
		pr_err("The Subject Public Key's hash does not match the %s.",
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
		error = pr_err("%s extension contains an authorityCertIssuer.",
		    ext_aki()->name);
		goto end;
	}
	if (aki->serial != NULL) {
		error = pr_err("%s extension contains an authorityCertSerialNumber.",
		    ext_aki()->name);
		goto end;
	}

	state = state_retrieve();
	if (state == NULL) {
		error = -EINVAL;
		goto end;
	}

	parent = x509stack_peek(validation_certstack(state));
	if (parent == NULL) {
		error = pr_err("Certificate has no parent.");
		goto end;
	}

	error = validate_public_key_hash(parent, aki->keyid);

end:
	AUTHORITY_KEYID_free(aki);
	return error;
}
