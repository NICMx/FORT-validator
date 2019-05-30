#include "object/ghostbusters.h"

#include "log.h"
#include "thread_var.h"
#include "asn1/oid.h"
#include "asn1/signed_data.h"
#include "object/signed_object.h"
#include "vcard.h"

static int
handle_vcard(OCTET_STRING_t *vcard, void *arg)
{
	return handle_ghostbusters_vcard(vcard);
}

int
ghostbusters_traverse(struct rpki_uri *uri, struct rpp *pp)
{
	static OID oid = OID_GHOSTBUSTERS;
	struct oid_arcs arcs = OID2ARCS("ghostbusters", oid);
	struct signed_object_args sobj_args;
	int error;

	pr_debug_add("Ghostbusters '%s' {", uri_get_printable(uri));
	fnstack_push_uri(uri);

	error = signed_object_args_init(&sobj_args, uri, rpp_crl(pp), true);
	if (error)
		goto end1;

	error = signed_object_decode(&sobj_args, &arcs, handle_vcard, NULL);
	if (error)
		goto end2;

	error = refs_validate_ee(&sobj_args.refs, pp, sobj_args.uri);

end2:
	signed_object_args_cleanup(&sobj_args);
end1:
	pr_debug_rm("}");
	fnstack_pop();
	return error;
}
