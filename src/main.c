#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <openssl/objects.h>

#include "common.h"
#include "config.h"
#include "debug.h"
#include "log.h"
#include "rpp.h"
#include "thread_var.h"
#include "object/certificate.h"
#include "object/manifest.h"
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
	    "rpkiManifest",
	    "RPKI Manifest (RFC 6487)");
	printf("rpkiManifest registered. Its nid is %d.\n", NID_rpkiManifest);

	NID_signedObject = OBJ_create("1.3.6.1.5.5.7.48.11",
	    "signedObject",
	    "RPKI Signed Object (RFC 6487)");
	printf("signedObject registered. Its nid is %d.\n", NID_signedObject);

	NID_rpkiNotify = OBJ_create("1.3.6.1.5.5.7.48.13",
	    "rpkiNotify",
	    "RPKI Update Notification File (RFC 8182)");
	printf("rpkiNotify registered. Its nid is %d.\n", NID_rpkiNotify);

	NID_certPolicyRpki = OBJ_create("1.3.6.1.5.5.7.14.2",
	    "id-cp-ipAddr-asNumber (RFC 6484)",
	    "Certificate Policy (CP) for the Resource PKI (RPKI)");
	printf("certPolicyRpki registered. Its nid is %d.\n", NID_certPolicyRpki);

	/* TODO implement RFC 8360 */
	NID_certPolicyRpkiV2 = OBJ_create("1.3.6.1.5.5.7.14.3",
	    "id-cp-ipAddr-asNumber-v2 (RFC 8360)",
	    "Certificate Policy for Use with Validation Reconsidered in the RPKI");
	printf("certPolicyRpkiV2 registered. Its nid is %d.\n",
	    NID_certPolicyRpkiV2);
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
	 */

	struct validation *state;
	int error;

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

	error = certificate_traverse(NULL, uri, NULL, true);
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

static int
parse_max_depth(struct rpki_config *config, char *str)
{
	/*
	 * It cannot be UINT_MAX, because then the actual number will overflow
	 * and will never be bigger than this.
	 */
	const unsigned int MAX = UINT_MAX - 1;
	unsigned long max_depth;

	errno = 0;
	max_depth = strtoul(str, NULL, 10);
	if (errno) {
		return pr_errno(errno,
		    "'%s' is not an unsigned integer, or is too big (max: %u)",
		    str, MAX);
	}

	if (max_depth > MAX)
		return pr_err("The number '%s' is too big (max: %u)", str, MAX);

	config->maximum_certificate_depth = max_depth;
	return 0;
}

static int
handle_args(int argc, char **argv)
{
	struct rpki_config config;
	int opt, error = 0;

	static struct option long_options[] = {
		{"tal", no_argument, NULL, 't'},
		{"local_repository", required_argument, NULL, 'l'},
		{"disable_rsync", no_argument, 0, 'r'},
		{"shuffle_uris", no_argument, 0, 's'},
		{0,0,0,}
	};

	config.disable_rsync = false;
	config.shuffle_uris = false;
	config.local_repository = NULL;
	config.tal = NULL;
	config.maximum_certificate_depth = 32;

	while ((opt = getopt_long(argc, argv, "t:l:rsm:", long_options, NULL))
	    != -1) {
		switch (opt) {
		case 't' :
			config.tal = optarg;
			break;
		case 'l' :
			config.local_repository = optarg;
			break;
		case 'r':
			config.disable_rsync = true;
			break;
		case 's':
			config.shuffle_uris = true;
			break;
		case 'm':
			error = parse_max_depth(&config, optarg);
			break;
		default:
			return pr_err("some usage hints.");/* TODO */
		}
	}

	if (config.tal == NULL) {
		fprintf(stderr, "Missing flag --tal <file>\n");
		error = -EINVAL;
	}
	if (config.local_repository == NULL) {
		fprintf(stderr, "Missing flag --local_repository <dir>\n");
		error = -EINVAL;
	}

	pr_debug("TAL file : %s", config.tal);
	pr_debug("Local repository : %s", config.local_repository);
	pr_debug("Disable rsync : %s", config.disable_rsync
	    ? "true" : "false");
	pr_debug("shuffle uris : %s", config.shuffle_uris
	    ? "true" : "false");
	pr_debug("Maximum certificate depth : %u",
	    config.maximum_certificate_depth);

	if (!error)
		config_set(&config);
	return error;
}

int
main(int argc, char **argv)
{
	struct tal *tal;
	int error;

	error = handle_args(argc, argv);
	if (error)
		return error;
	print_stack_trace_on_segfault();

	error = rsync_init();
	if (error)
		return error;

	add_rpki_oids();
	thvar_init();
	fnstack_store();
	fnstack_push(config_get_tal());

	error = tal_load(config_get_tal(), &tal);
	if (!error) {
		if (config_get_shuffle_uris())
			tal_shuffle_uris(tal);
		error = foreach_uri(tal, handle_tal_uri);
		error = (error >= 0) ? 0 : error;
		tal_destroy(tal);
	}

	rsync_destroy();
	return error;
}
