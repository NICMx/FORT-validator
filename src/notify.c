#include "notify.h"

#include <err.h>
#include "clients.h"
#include "rtr/pdu_sender.h"
#include "rtr/db/vrps.h"

static int
send_notify(int fd, uint8_t rtr_version)
{
	struct sender_common common;
	uint32_t serial;
	uint16_t session_id;

	serial = get_last_serial_number();
	session_id = get_current_session_id(rtr_version);
	init_sender_common(&common, fd, rtr_version, &session_id, &serial,
	    NULL);
	return send_serial_notify_pdu(&common);
}

void
notify_clients(void)
{
	struct client *clients, *ptr;
	size_t clients_len;
	int error;

	clients_len = client_list(&clients);
	for (ptr = clients; (ptr - clients) < clients_len; ptr++) {
		/* Send Serial Notify PDU */
		error = send_notify(ptr->fd, ptr->rtr_version);
		/* Error? Log it */
		if (error)
			warnx("Error sending notify PDU to client");
	}
}
