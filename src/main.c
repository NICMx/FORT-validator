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

	NID_rpkiNotify = OBJ_create("1.3.6.1.5.5.7.48.13",
	    "id-ad-rpkiNotify (RFC 8182)",
	    /* TODO */ "Blah blah");
	printf("rpkiNotify registered. Its nid is %d.\n", NID_rpkiNotify);
}

/**
 * Performs the whole validation walkthrough on uri @uri, which is assumed to
 * have been extracted from a TAL.
 */
static int
handle_tal_uri(char const *uri)
{
	struct validation *state;
	char *cert_file;
	int error;

	error = uri_g2l(uri, &cert_file);
	if (error)
		return error;

	error = download_files(uri);
	if (error)
		return error;

	error = validation_create(&state, cert_file);
	if (error)
		goto end1;

	pr_debug_add("TAL URI %s {", uri);

	if (!is_certificate(uri)) {
		pr_err("TAL file does not point to a certificate. (Expected .cer, got '%s')",
		    uri);
		error = -ENOTSUPPORTED;
		goto end2;
	}

	fnstack_push(uri);
	error = certificate_traverse(validation_peek_cert(state));
	fnstack_pop();

end2:
	pr_debug_rm("}");
	validation_destroy(state);
end1:
	free(cert_file);
	return error;
}

int
main(int argc, char **argv)
{
	struct tal *tal;
	int error;
	bool is_rsync_active = true;

	print_stack_trace_on_segfault();

	if (argc < 3) {
		pr_err("Repository path as first argument and TAL file as second argument, please.");
		return -EINVAL;
	}

	if (argc >= 4)
		is_rsync_active = false;

	error = rsync_init(is_rsync_active);
	if (error)
		return error;

	add_rpki_oids();
	thvar_init();
	fnstack_store();
	fnstack_push(argv[2]);

	repository = argv[1];

	error = tal_load(argv[2], &tal);
	if (error)
		return error;

	error = foreach_uri(tal, handle_tal_uri);

	tal_destroy(tal);
	rsync_destroy();
	return error;
}
