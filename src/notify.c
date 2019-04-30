#include "notify.h"

#include <err.h>
#include "clients.h"
#include "rtr/pdu_sender.h"
#include "rtr/db/vrps.h"

static int
send_notify(struct client const *client, void *arg)
{
	struct sender_common common;
	uint32_t *serial = arg;
	uint16_t session_id;
	int error;

	/* Send Serial Notify PDU */
	session_id = get_current_session_id(client->rtr_version);
	init_sender_common(&common, client->fd, client->rtr_version,
	    &session_id, serial, NULL);
	error = send_serial_notify_pdu(&common);

	/* Error? Log it */
	if (error)
		warnx("Error sending notify PDU to client");

	return 0; /* Do not interrupt notify to other clients */
}

int
notify_clients(void)
{
	uint32_t serial;
	int error;

	error = get_last_serial_number(&serial);
	if (error)
		return error;

	return clients_foreach(send_notify, &serial);
}
