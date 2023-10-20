#include "rtr/pdu.h"

#include <errno.h>

#include "alloc.h"
#include "common.h"
#include "log.h"
#include "types/address.h"
#include "rtr/err_pdu.h"
#include "rtr/pdu_handler.h"
#include "rtr/pdu_sender.h"

char const *
pdutype2str(enum pdu_type type)
{
	switch (type) {
	case PDU_TYPE_SERIAL_NOTIFY:
		return "Serial Notify PDU";
	case PDU_TYPE_SERIAL_QUERY:
		return "Serial Query PDU";
	case PDU_TYPE_RESET_QUERY:
		return "Reset Query PDU";
	case PDU_TYPE_CACHE_RESPONSE:
		return "Cache Response PDU";
	case PDU_TYPE_IPV4_PREFIX:
		return "IPv4 Prefix PDU";
	case PDU_TYPE_IPV6_PREFIX:
		return "IPv6 Prefix PDU";
	case PDU_TYPE_END_OF_DATA:
		return "End of Data PDU";
	case PDU_TYPE_CACHE_RESET:
		return "Cache Reset PDU";
	case PDU_TYPE_ROUTER_KEY:
		return "Router Key PDU";
	case PDU_TYPE_ERROR_REPORT:
		return "Error Report PDU";
	}

	return "unknown PDU";
}

