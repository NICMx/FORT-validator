#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "rtr/rtr.h"
#include "clients.h"
#include "configuration.h"
#include "csv.h"
#include "updates_daemon.h"
#include "vrps.h"

/*
 * This program is an RTR server.
 *
 * RTR ("RPKI-to-Router") is a protocol (defined in RFCs 6810 and 8210) that
 * reports the work of an RPKI validator (cryptographcally-verified
 * attestations that define the ASN that owns a given routing prefix). It is
 * normally served to routers who wish to verify BGP claims.
 */
int
main(int argc, char *argv[])
{
	int err;
	char *json_file = NULL;
	int c;

	while ((c = getopt(argc, argv, "f:")) != -1) {
		switch (c) {
		case 'f':
			json_file = optarg;
			break;
		case '?':
			fprintf(stdout, "usage: %s -f <file name>\n", argv[0]);
			return 0;
		}
	}

	if (json_file == NULL) {
		fprintf(stderr, "Missing flag '-f <file name>'\n");
		return -EINVAL;
	}

	err = config_init(json_file);
	if (err)
		goto end1;

	err = deltas_db_init();
	if (err)
		goto end1;

	err = clients_db_init();
	if (err)
		goto end2;

	err = csv_parse_vrps_file();
	if (err)
		goto end3;

	err = updates_daemon_init();
	if (err)
		goto end3;

	err = rtr_listen();

end3:
	clients_db_destroy();
end2:
	deltas_db_destroy();
end1:
	config_cleanup();
	return err;
}
