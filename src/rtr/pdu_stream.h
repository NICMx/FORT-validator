#ifndef SRC_RTR_PDU_STREAM_H_
#define SRC_RTR_PDU_STREAM_H_

#include <arpa/inet.h>
#include <netinet/in.h>
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
#define PS_NEED_POLL(s) (((s)->flags & (PSF_POLLIN | PSF_CLAIMED | PSF_EOS)) == 0)

#define PS_ENABLE(s, f) (s)->flags |= PSF_##f
#define PS_DISABLE(s, f) (s)->flags &= ~PSF_##f

struct pdu_stream { /* It's an *input* stream. */
	int fd;
	char addr[INET6_ADDRSTRLEN];	/* Printable address of the client. */
	int flags;			/* Requires lock */
	int rtr_version;		/* -1: unset; > 0: version number */
	int session;			/* -1: unset; > 0: session */

	unsigned char buffer[RTRPDU_MAX_LEN2];
	/* buffer's active bytes */
	unsigned char *start;
	unsigned char *end;
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

struct rtr_request_list {
	TAILQ_HEAD(rtr_requests, rtr_request) nodes;
	unsigned int count;
};

struct pdu_stream *pdustream_create(int, char const *);
void pdustream_destroy(struct pdu_stream *);

bool pdustream_parse(struct pdu_stream *, struct rtr_request_list *);
void pdustream_disable_read(struct pdu_stream *);

void rtreq_destroy(struct rtr_request *);

struct rtr_request *rtreqlist_pop(struct rtr_request_list *);
void rtreqlist_clear(struct rtr_request_list *);

#endif /* SRC_RTR_PDU_STREAM_H_ */
