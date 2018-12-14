#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "rtr/rtr.h"
#include "configuration.h"
/*
 * This program is an RTR server.
 *
 * RTR ("RPKI-to-Router") is a protocol (defined in RFCs 6810 and 8210) that
 * reports the work of an RPKI validator (cryptographcally-verified attestations
 * that define the ASN that owns a given routing prefix). It is normally served
 * to routers who wish to verify BGP claims.
 */
int
main(int argc, char *argv[])
{
	int err = 0;
	char *json_file = NULL;
	struct rtr_config *config;
	int c;
	int fflag=0;
	static char usage[] = "usage: %s -f fname \n";

	puts("!!!Hello World!!!");

	while ((c = getopt(argc, argv, "f:")) != -1)
		switch (c) {
		case 'f':
			fflag = 1;
			json_file = optarg;
			break;
		case '?':
			err = 1;
			break;
		}

	if (fflag == 0) { /* -f was mandatory */
		fprintf(stderr, "%s: missing -f option\n", argv[0]);
		fprintf(stderr, usage, argv[0]);
		exit(1);
	} else if (err) {
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}

	err = read_config_from_file(json_file, &config);
	if (err)
		return err;

	err = rtr_listen(config->host_address, config->host_port);
	if (config)
		free_rtr_config(config);

	if (err)
		return err;

	return EXIT_SUCCESS;
}
