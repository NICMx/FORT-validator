#include <err.h>
#include <errno.h>
#include <getopt.h>

#include "common.h"
#include "config.h"
#include "debug.h"
#include "extension.h"
#include "log.h"
#include "nid.h"
#include "rpp.h"
#include "thread_var.h"
#include "object/certificate.h"
#include "object/manifest.h"
#include "object/tal.h"
#include "rsync/rsync.h"

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
		return pr_warn("TAL URI '%s' could not be RSYNC'd.");

	error = validation_prepare(&state, tal);
	if (error)
		return -abs(error);

	pr_debug_add("TAL URI '%s' {", uri_get_printable(uri));

	if (!uri_is_certificate(uri)) {
		pr_err("TAL file does not point to a certificate. (Expected .cer, got '%s')",
		    uri_get_printable(uri));
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

int
main(int argc, char **argv)
{
	struct tal *tal;
	int error;

	print_stack_trace_on_segfault();

	thvar_init();
	fnstack_store();

	error = handle_flags_config(argc, argv);
	if (error)
		return error;

	error = rsync_init();
	if (error)
		goto end1;

	error = nid_init();
	if (error)
		goto end2;
	error = extension_init();
	if (error)
		goto end2;
	fnstack_push(config_get_tal());

	error = tal_load(config_get_tal(), &tal);
	if (!error) {
		if (config_get_shuffle_uris())
			tal_shuffle_uris(tal);

		error = foreach_uri(tal, handle_tal_uri);
		if (error > 0)
			error = 0;
		else if (error == 0)
			error = pr_err("None of the URIs of the TAL yielded a successful traversal.");

		tal_destroy(tal);
	}

end2:
	rsync_destroy();
end1:
	free_rpki_config();
	return error;
}
