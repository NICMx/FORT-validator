#include "pdu_handler.h"

#include <err.h>
#include <errno.h>

static int warn_unexpected_pdu(char *);

static int
warn_unexpected_pdu(char *pdu_name)
{
	warnx("RTR servers are not expected to receive %s PDUs, but we got one anyway (Closing socket.)",
	    pdu_name);
	return -EINVAL;
}

int
handle_serial_notify_pdu(void *pdu)
{
	return warn_unexpected_pdu("Serial Notify");
}

int
handle_serial_query_pdu(void *pdu)
{
	/* TODO */
	return -EUNIMPLEMENTED;
}

int
handle_reset_query_pdu(void *pdu)
{
	/* TODO */
	return -EUNIMPLEMENTED;
}

int
handle_cache_response_pdu(void *pdu)
{
	return warn_unexpected_pdu("Cache Response");
}

int
handle_ipv4_prefix_pdu(void *pdu)
{
	return warn_unexpected_pdu("IPv4 Prefix");
}

int
handle_ipv6_prefix_pdu(void *pdu)
{
	return warn_unexpected_pdu("IPv6 Prefix");
}

int
handle_end_of_data_pdu(void *pdu)
{
	return warn_unexpected_pdu("End of Data");
}

int
handle_cache_reset_pdu(void *pdu)
{
	return warn_unexpected_pdu("Cache Reset");
}

int
handle_error_report_pdu(void *pdu)
{
	/* TODO */
	return -EUNIMPLEMENTED;
}
