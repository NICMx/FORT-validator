#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <openssl/objects.h>

#include "certificate.h"
#include "common.h"
#include "debug.h"
#include "manifest.h"
#include "tal.h"

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
	pr_debug("rpkiManifest registered. Its nid is %d.", NID_rpkiManifest);

	NID_rpkiNotify = OBJ_create("1.3.6.1.5.5.7.48.13",
	    "id-ad-rpkiNotify (RFC 8182)",
	    /* TODO */ "Blah blah");
	pr_debug("rpkiNotify registered. Its nid is %d.", NID_rpkiNotify);
}

/**
 * Performs the whole validation walkthrough on uri @uri, which is assumed to
 * have been extracted from a TAL.
 */
static int
handle_tal_uri(char const *uri)
{
	char *cert_file;
	int error;

	pr_debug_add("TAL URI %s {", uri);

	if (!is_certificate(uri)) {
		warnx("TAL file does not seem to point to a certificate.");
		warnx("(Expected .cer file, got '%s')", uri);
		error = -ENOTSUPPORTED;
		goto end;
	}

	error = uri_g2l(uri, &cert_file);
	if (error)
		goto end;

	error = handle_certificate(cert_file);
	free(cert_file);

end:
	pr_debug0_rm("}");
	return error;
}

int
main(int argc, char **argv)
{
	struct tal *tal;
	int error;

	if (argc < 3) {
		warnx("Repository path as first argument and TAL file as second argument, please.");
		return -EINVAL;
	}

	add_rpki_oids();

	repository = argv[1];

	error = tal_load(argv[2], &tal);
	if (error)
		return error;

	error = foreach_uri(tal, handle_tal_uri);

	tal_destroy(tal);
	return error;
}
