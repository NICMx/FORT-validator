#include "object/ghostbusters.h"

#include "asn1/oid.h"
#include "log.h"
#include "object/signed_object.h"
#include "object/vcard.h"
#include "thread_var.h"

static int
handle_vcard(struct signed_object *sobj)
{
	return handle_ghostbusters_vcard(
		sobj->sdata->encapContentInfo.eContent
	);
}

int
ghostbusters_traverse(struct rpki_uri *uri, struct rpp *pp)
{
	static OID oid = OID_GHOSTBUSTERS;
	struct oid_arcs arcs = OID2ARCS("ghostbusters", oid);
	struct signed_object sobj;
	struct ee_cert ee;
	STACK_OF(X509_CRL) *crl;
	int error;

	/* Prepare */
	pr_val_debug("Ghostbusters '%s' {", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	/* Decode */
	error = signed_object_decode(&sobj, uri);
	if (error)
		goto revert_log;

	/* Prepare validation arguments */
	error = rpp_crl(pp, &crl);
	if (error)
		goto revert_sobj;
	eecert_init(&ee, crl, true);

	/* Validate everything */
	error = signed_object_validate(&sobj, &arcs, &ee);
	if (error)
		goto revert_args;
	error = handle_vcard(&sobj);
	if (error)
		goto revert_args;
	error = refs_validate_ee(&ee.refs, pp, uri);

revert_args:
	eecert_cleanup(&ee);
revert_sobj:
	signed_object_cleanup(&sobj);
revert_log:
	pr_val_debug("}");
	fnstack_pop();
	return error;
}
