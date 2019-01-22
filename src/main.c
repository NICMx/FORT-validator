#include <err.h>
#include <errno.h>
#include <openssl/objects.h>

#include "common.h"
#include "debug.h"
#include "log.h"
#include "thread_var.h"
#include "object/certificate.h"
#include "object/tal.h"
#include "rsync/rsync.h"

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

	NID_rpkiNotify = OBJ_create("1.3.6.1.5.5.7.48.13",
		    "id-ad-rpkiNotify (RFC 8182)",
		    /* TODO */ "Blah blah");
	printf("rpkiNotify registered. Its nid is %d.\n", NID_rpkiNotify);
}

static int
handle_tal_certificate(struct rpki_uri const *uri)
{
	X509 *cert;
	int error;

	fnstack_push(uri->global);
	error = certificate_load(uri, &cert);
	if (error)
		goto end;

	error = certificate_validate_rfc6487(cert, true);
	if (error)
		goto revert;
	error = certificate_traverse_ta(cert, NULL);

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
handle_tal_uri(struct tal *tal, struct rpki_uri const *uri)
{
	/*
	 * Because of the way the foreach iterates, this function must return
	 *
	 * - 0 on soft errors.
	 * - `> 0` on URI handled successfully.
	 * - `< 0` on hard errors.
	 *
	 * A "soft error" is "the connection to the preferred URI fails, or the
	 * retrieved CA certificate public key does not match the TAL public
	 * key." (RFC 7730)
	 *
	 * A "hard error" is any other error.
	 *
	 * TODO this will probably need an update after the merge.
	 */

	struct validation *state;
	int error;

	/* TODO this probably needs the state... */
	error = download_files(uri);
	if (error)
		return 0;

	error = validation_prepare(&state, tal);
	if (error)
		return -abs(error);

	pr_debug_add("TAL URI %s {", uri->global);

	if (!uri_is_certificate(uri)) {
		pr_err("TAL file does not point to a certificate. (Expected .cer, got '%s')",
		    uri->global);
		error = -EINVAL;
		goto end;
	}

	error = handle_tal_certificate(uri);
	if (error) {
		switch (validation_pubkey_state(state)) {
		case PKS_INVALID:
			error = 0;
			break;
		case PKS_VALID:
		case PKS_UNTESTED:
			error = -abs(error);
			break;
		}
	} else {
		error = 1;
	}

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
	bool is_rsync_active = true;
	bool shuffle_uris = false;

	print_stack_trace_on_segfault();

	if (argc < 3)
		return pr_err("Repository path as first argument and TAL file as second argument, please.");
	if (argc >= 4)
		is_rsync_active = false;
	if (argc >= 5)
		shuffle_uris = true; /* TODO lol fix this */

	error = rsync_init(is_rsync_active);
	if (error)
		return error;

	add_rpki_oids();
	thvar_init();
	fnstack_store();
	fnstack_push(argv[2]);

	repository = argv[1];
	repository_len = strlen(repository);

	error = tal_load(argv[2], &tal);
	if (!error) {
		if (shuffle_uris)
			tal_shuffle_uris(tal);
		error = foreach_uri(tal, handle_tal_uri);
		error = (error >= 0) ? 0 : error;
		tal_destroy(tal);
	}

	rsync_destroy();
	return error;
}
