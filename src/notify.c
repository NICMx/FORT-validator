#include "notify.h"

#include <err.h>
#include <stddef.h>
#include "clients.h"
#include "log.h"
#include "rtr/pdu_sender.h"
#include "rtr/db/vrps.h"

static int
send_notify(struct client const *client, void *arg)
{
	struct sender_common common;
	serial_t *serial = arg;
	int error;

	/* Send Serial Notify PDU */
	init_sender_common(&common, client->fd, client->rtr_version);
	error = send_serial_notify_pdu(&common, *serial);

	/* Error? Log it... */
	if (error)
		pr_warn("Error code %d sending notify PDU to client.", error);

	return 0; /* ...but do not interrupt notify to other clients */
}

int
notify_clients(void)
{
	serial_t serial;
	int error;

	error = get_last_serial_number(&serial);
	if (error)
		return error;

	return clients_foreach(send_notify, &serial);
}
