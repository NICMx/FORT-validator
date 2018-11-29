#ifndef SRC_RESOURCE_H_
#define SRC_RESOURCE_H_

#include <libcmscodec/ASIdentifiers.h>
#include <libcmscodec/ASIdOrRange.h>
#include <libcmscodec/IPAddressFamily.h>
#include <openssl/safestack.h>
#include <sys/queue.h>

struct resources;
struct restack;

struct resources *resources_create(void);
void resources_destroy(struct resources *);

int resources_add_ip(struct resources *, struct IPAddressFamily *,
    struct resources *);
int resources_add_asn(struct resources *, struct ASIdentifiers *,
    struct resources *);

int resources_join(struct resources *, struct resources *);

struct restack *restack_create(void);
void restack_destroy(struct restack *);

void restack_push(struct restack *, struct resources *);
struct resources *restack_pop(struct restack *);
struct resources *restack_peek(struct restack *);

#endif /* SRC_RESOURCE_H_ */
