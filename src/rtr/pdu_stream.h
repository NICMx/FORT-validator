#ifndef SRC_RTR_PDU_STREAM_H_
#define SRC_RTR_PDU_STREAM_H_

#include <sys/queue.h>
#include <stdbool.h>

#include "rtr/pdu.h"

struct rtr_request;

struct pdu_stream { /* It's an *input* stream. */
	int fd;
	char addr[INET6_ADDRSTRLEN];	/* Printable address of the client. */
	int rtr_version;		/* -1: unset; > 0: version number */
	int session;			/* -1: unset; > 0: session */

	unsigned char buffer[RTRPDU_MAX_LEN2];
	/* buffer's active bytes */
	unsigned char *start;
	unsigned char *end;

	bool claimed;
	TAILQ_HEAD(, rtr_request) requests; /* No more than 4 nodes */
	unsigned int reqcount;

	bool eos; /* end of (input) stream */
};

struct rtr_request {
	int fd;
	char client_addr[INET6_ADDRSTRLEN];

	struct pdu_stream *stream;
	TAILQ_ENTRY(rtr_request) lh;

	struct {
		enum rtr_version rtr_version;
		enum pdu_type type;

		/* Deserialized version */
		union {
			struct {
				uint16_t session_id;
				uint32_t serial_number;
			} sq; /* Serial Query */
		} obj;

		/*
		 * Serialized version.
		 * Can be truncated; use for responding errors only.
		 */
		struct rtr_buffer raw;
	} pdu;
};

struct pdu_stream *pdustream_create(int, char const *);
void pdustream_clear_requests(struct pdu_stream *);
void pdustream_destroy(struct pdu_stream *);

bool pdustream_parse(struct pdu_stream *, bool *);

void rtreq_destroy(struct rtr_request *);

#endif /* SRC_RTR_PDU_STREAM_H_ */
