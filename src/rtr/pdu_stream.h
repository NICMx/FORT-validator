#ifndef SRC_RTR_PDU_STREAM_H_
#define SRC_RTR_PDU_STREAM_H_

#include <sys/queue.h>
#include <stdbool.h>

#include "rtr/pdu.h"

struct rtr_request;

#define PSF_POLLIN  (1 << 0) /* needs to be claimed? */
#define PSF_CLAIMED (1 << 1) /* thread currently handling requests? */
#define PSF_EOS     (1 << 2) /* end of (input) stream? */

#define PS_POLLIN(s) ((s)->flags & PSF_POLLIN)
#define PS_CLAIMED(s) ((s)->flags & PSF_CLAIMED)
#define PS_EOS(s) ((s)->flags & PSF_EOS)

#define PS_ENABLE(s, f) (s)->flags |= PSF_##f
#define PS_DISABLE(s, f) (s)->flags &= ~PSF_##f

struct pdu_stream { /* It's an *input* stream. */
	int fd;
	char addr[INET6_ADDRSTRLEN];	/* Printable address of the client. */
	int flags;
	int rtr_version;		/* -1: unset; > 0: version number */
	int session;			/* -1: unset; > 0: session */

	unsigned char buffer[RTRPDU_MAX_LEN2];
	/* buffer's active bytes */
	unsigned char *start;
	unsigned char *end;

	TAILQ_HEAD(, rtr_request) requests; /* No more than 4 nodes */
	unsigned int reqcount;
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
