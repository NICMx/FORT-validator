#ifndef SRC_STATE_H_
#define SRC_STATE_H_

#include <openssl/x509.h>
#include "cert_stack.h"
#include "validation_handler.h"
#include "object/tal.h"
#include "rsync/rsync.h"
#include "rrdp/db/db_rrdp_uris.h"

struct validation;

int validation_prepare(struct validation **, struct tal *,
    struct validation_handler *);
void validation_destroy(struct validation *);

struct tal *validation_tal(struct validation *);
X509_STORE *validation_store(struct validation *);
struct cert_stack *validation_certstack(struct validation *);
struct uri_list *validation_rsync_visited_uris(struct validation *);

enum pubkey_state {
	PKS_VALID,
	PKS_INVALID,
	PKS_UNTESTED,
};

void validation_pubkey_valid(struct validation *);
void validation_pubkey_invalid(struct validation *);
enum pubkey_state validation_pubkey_state(struct validation *);

char *validation_get_ip_buffer1(struct validation *);
char *validation_get_ip_buffer2(struct validation *);

struct validation_handler const *
validation_get_validation_handler(struct validation *);

struct db_rrdp_uri *validation_get_rrdp_uris(struct validation *);
char const *validation_get_rrdp_workspace(struct validation *);

#endif /* SRC_STATE_H_ */
