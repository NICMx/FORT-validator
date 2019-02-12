#include "nid.h"

#include <errno.h>
#include <openssl/objects.h>

#include "log.h"

static int NID_rpkiManifest;
static int NID_signedObject;
static int NID_rpkiNotify;
static int NID_certPolicyRpki;
static int NID_certPolicyRpkiV2;
static int NID_ipAddrBlocksv2;
static int NID_autonomousSysIdsv2;

static int
register_oid(const char *oid, const char *sn, const char *ln)
{
	int nid;

	nid = OBJ_create(oid, sn, ln);
	if (nid == 0)
		return crypto_err("Unable to register the %s NID.", sn);

	printf("%s registered. Its nid is %d.\n", sn, nid);
	return nid;
}

/**
 * Registers the RPKI-specific OIDs in the SSL library.
 * LibreSSL needs it; not sure about OpenSSL.
 */
int
nid_init(void)
{
	NID_rpkiManifest = register_oid("1.3.6.1.5.5.7.48.10",
	    "rpkiManifest",
	    "RPKI Manifest (RFC 6487)");
	if (NID_rpkiManifest == 0)
		return -EINVAL;

	NID_signedObject = register_oid("1.3.6.1.5.5.7.48.11",
	    "signedObject",
	    "RPKI Signed Object (RFC 6487)");
	if (NID_signedObject == 0)
		return -EINVAL;

	NID_rpkiNotify = register_oid("1.3.6.1.5.5.7.48.13",
	    "rpkiNotify",
	    "RPKI Update Notification File (RFC 8182)");
	if (NID_rpkiNotify == 0)
		return -EINVAL;

	NID_certPolicyRpki = register_oid("1.3.6.1.5.5.7.14.2",
	    "id-cp-ipAddr-asNumber (RFC 6484)",
	    "Certificate Policy (CP) for the Resource PKI (RPKI)");
	if (NID_certPolicyRpki == 0)
		return -EINVAL;

	NID_certPolicyRpkiV2 = register_oid("1.3.6.1.5.5.7.14.3",
	    "id-cp-ipAddr-asNumber-v2 (RFC 8360)",
	    "Certificate Policy for Use with Validation Reconsidered in the RPKI");
	if (NID_certPolicyRpkiV2 == 0)
		return -EINVAL;

	NID_ipAddrBlocksv2 = register_oid("1.3.6.1.5.5.7.1.28",
	    "id-pe-ipAddrBlocks-v2",
	    "Amended IP Resources (RFC 8360)");
	if (NID_ipAddrBlocksv2 == 0)
		return -EINVAL;

	NID_autonomousSysIdsv2 = register_oid("1.3.6.1.5.5.7.1.29",
	    "id-pe-autonomousSysIds-v2",
	    "Amended AS Resources (RFC 8360)");
	if (NID_autonomousSysIdsv2 == 0)
		return -EINVAL;

	return 0;
}

int nid_rpkiManifest(void)
{
	return NID_rpkiManifest;
}

int nid_signedObject(void)
{
	return NID_signedObject;
}

int nid_rpkiNotify(void)
{
	return NID_rpkiNotify;
}

int nid_certPolicyRpki(void)
{
	return NID_certPolicyRpki;
}

int nid_certPolicyRpkiV2(void)
{
	return NID_certPolicyRpkiV2;
}

int nid_ipAddrBlocksv2(void)
{
	return NID_ipAddrBlocksv2;
}

int nid_autonomousSysIdsv2(void)
{
	return NID_autonomousSysIdsv2;
}
