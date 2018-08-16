#include <stdio.h>
#include <stdlib.h>

#include "rtr/rtr.h"

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
	puts("!!!Hello World!!!");
	rtr_listen();
	return EXIT_SUCCESS;
}
