#ifndef SRC_RTR_PDU_STREAM_H_
#define SRC_RTR_PDU_STREAM_H_

#include <sys/queue.h>

#include "rtr/pdu.h"
#include "rtr/rtr.h"
#include "data_structure/array_list.h"

struct pdu_stream; /* It's an *input* stream. */

struct rtr_pdu {
	/* Deserialized version */
	union {
		struct pdu_header hdr;
		struct serial_query_pdu sq;
		struct reset_query_pdu rq;
		struct error_report_pdu er;
	} obj;

	/*
	 * Serialized version.
	 * Can be truncated; use for responding errors only.
	 */
	struct rtr_buffer raw;

	STAILQ_ENTRY(rtr_pdu) hook;
};

struct rtr_request {
	int fd;
	char client_addr[INET6_ADDRSTRLEN];

	/*
	 * It's not sensible for a request to contain multiple PDUs,
	 * but I don't know how much buffering the underlying socket has.
	 */
	STAILQ_HEAD(, rtr_pdu) pdus;

	bool eos; /* end of stream */
};

struct pdu_stream *pdustream_create(int, char const *);
void pdustream_destroy(struct pdu_stream **);

int pdustream_next(struct pdu_stream *, struct rtr_request **);
int pdustream_fd(struct pdu_stream *);
char const *pdustream_addr(struct pdu_stream *);
int pdustream_version(struct pdu_stream *);

void rtreq_destroy(struct rtr_request *);

#endif /* SRC_RTR_PDU_STREAM_H_ */
