#include <err.h>
#include <errno.h>
#include <openssl/objects.h>

#include "common.h"
#include "debug.h"
#include "log.h"
#include "thread_var.h"
#include "crypto/hash.h"
#include "object/certificate.h"
#include "object/tal.h"

/**
 * Registers the RPKI-specific OIDs in the SSL library.
 * LibreSSL needs it; not sure about OpenSSL.
 */
static void
add_rpki_oids(void)
{
	NID_rpkiManifest = OBJ_create("1.3.6.1.5.5.7.48.10",
	    "id-ad-rpkiManifest (RFC 6487)",
	    "Resource Public Key Infrastructure (RPKI) manifest access method");
	printf("rpkiManifest registered. Its nid is %d.\n", NID_rpkiManifest);

	NID_signedObject = OBJ_create("1.3.6.1.5.5.7.48.11",
	    "id-ad-signedObject (RFC 6487)",
	    /* TODO */ "");
	printf("signedObject registered. Its nid is %d.\n", NID_signedObject);
}

static int
handle_tal_certificate(char *uri)
{
	X509 *cert;
	int error;

	fnstack_push(uri);
	error = certificate_load(uri, &cert);
	if (error)
		goto end;

	error = certificate_validate_rfc6487(cert, true);
	if (error)
		goto revert;
	error = certificate_traverse_ca(cert, NULL);

revert:
	X509_free(cert);
end:
	fnstack_pop();
	return error;
}

/**
 * Performs the whole validation walkthrough on uri @uri, which is assumed to
 * have been extracted from a TAL.
 */
static int
handle_tal_uri(struct tal *tal, char const *guri)
{
	struct validation *state;
	char *luri;
	int error;

	error = validation_prepare(&state, tal);
	if (error)
		return error;

	pr_debug_add("TAL URI %s {", guri);

	if (!is_certificate(guri)) {
		pr_err("TAL file does not point to a certificate. (Expected .cer, got '%s')",
		    guri);
		error = -ENOTSUPPORTED;
		goto end;
	}

	error = uri_g2l(guri, strlen(guri), &luri);
	if (error)
		return error;

	error = handle_tal_certificate(luri);
	free(luri);

end:
	validation_destroy(state);
	pr_debug_rm("}");
	return error;
}

int
main(int argc, char **argv)
{
	struct tal *tal;
	int error;

	print_stack_trace_on_segfault();

	if (argc < 3)
		return pr_err("Repository path as first argument and TAL file as second argument, please.");

	error = hash_init();
	if (error)
		return error;

	add_rpki_oids();
	thvar_init();
	fnstack_store();
	fnstack_push(argv[2]);

	repository = argv[1];
	repository_len = strlen(repository);

	error = tal_load(argv[2], &tal);
	if (error)
		return error;

	error = foreach_uri(tal, handle_tal_uri);

	tal_destroy(tal);
	return error;
}
