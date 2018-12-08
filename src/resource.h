#ifndef SRC_RESOURCE_H_
#define SRC_RESOURCE_H_

#include <stdbool.h>
#include <libcmscodec/ASIdentifiers.h>
#include <libcmscodec/IPAddressFamily.h>
#include "address.h"

struct resources;

struct resources *resources_create(void);
void resources_destroy(struct resources *);

int resources_add_ip(struct resources *, struct IPAddressFamily *,
    struct resources *);
int resources_add_asn(struct resources *, struct ASIdentifiers *,
    struct resources *);

bool resources_contains_asn(struct resources *, ASId_t);
bool resources_contains_ipv4(struct resources *, struct ipv4_prefix *);
bool resources_contains_ipv6(struct resources *, struct ipv6_prefix *);

int resources_join(struct resources *, struct resources *);

struct restack;

struct restack *restack_create(void);
void restack_destroy(struct restack *);

void restack_push(struct restack *, struct resources *);
struct resources *restack_pop(struct restack *);
struct resources *restack_peek(struct restack *);

#endif /* SRC_RESOURCE_H_ */
