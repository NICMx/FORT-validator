#include "clients.h"

#include <errno.h>
#include "common.h"
#include "log.h"
#include "data_structure/uthash.h"

/*
 * TODO uthash panics on memory allocations...
 * http://troydhanson.github.io/uthash/userguide.html#_out_of_memory
 * TODO sem_wait(), sem_post(), sem_init() and sem_destroy() return error.
 */

#define SADDR_IN(addr) ((struct sockaddr_in *)addr)
#define SADDR_IN6(addr) ((struct sockaddr_in6 *)addr)

struct hashable_client {
	struct client meat;
	UT_hash_handle hh;
};

/** Hash table of clients */
struct hashable_client *table;
/** Read and Write locks */
static sem_t rlock, wlock;
/** Readers counter */
static unsigned int rcounter;

void
clients_db_init(void)
{
	table = NULL;
	sem_init(&rlock, 0, 1);
	sem_init(&wlock, 0, 1);
	rcounter = 0;
}

static int
create_client(int fd, struct sockaddr_storage *addr, uint8_t rtr_version,
    struct hashable_client **result)
{
	struct hashable_client *node;

	node = malloc(sizeof(struct hashable_client));
	if (node == NULL)
		return pr_enomem();

	node->meat.fd = fd;
	node->meat.family = addr->ss_family;
	switch (addr->ss_family) {
	case AF_INET:
		node->meat.sin = SADDR_IN(addr)->sin_addr;
		node->meat.sin_port = SADDR_IN(addr)->sin_port;
		break;
	case AF_INET6:
		node->meat.sin6 = SADDR_IN6(addr)->sin6_addr;
		node->meat.sin_port = SADDR_IN6(addr)->sin6_port;
		break;
	default:
		free(node);
		return pr_crit("Bad protocol: %u", addr->ss_family);
	}
	node->meat.rtr_version = rtr_version;

	*result = node;
	return 0;
}

/*
 * If the client whose file descriptor is @fd isn't already stored, store it.
 *
 * Code error -ERTR_VERSION_MISMATCH will be returned when a client exists but
 * its RTR version isn't the same as in the DB.
 */
int
clients_add(int fd, struct sockaddr_storage *addr, uint8_t rtr_version)
{
	struct hashable_client *new_client = NULL;
	struct hashable_client *old_client;
	int error;

	error = create_client(fd, addr, rtr_version, &new_client);
	if (error)
		return error;

	sem_wait(&wlock);

	HASH_FIND_INT(table, &fd, old_client);
	if (old_client == NULL) {
		HASH_ADD_INT(table, meat.fd, new_client);
		new_client = NULL;
	} else {
		/*
		 * Isn't ready to handle distinct version on clients
		 * reconnection, but for now there's no problem since only
		 * RTRv0 is supported.
		 */
		if (old_client->meat.rtr_version != rtr_version)
			error = -ERTR_VERSION_MISMATCH;
	}

	sem_post(&wlock);

	if (new_client != NULL)
		free(new_client);

	return error;
}

void
clients_forget(int fd)
{
	struct hashable_client *client;

	sem_wait(&wlock);

	HASH_FIND_INT(table, &fd, client);
	if (client != NULL)
		HASH_DEL(table, client);

	sem_post(&wlock);
}

int
clients_foreach(clients_foreach_cb cb, void *arg)
{
	struct hashable_client *client;
	int error = 0;

	read_lock(&rlock, &wlock, &rcounter);

	for (client = table; client != NULL; client = client->hh.next) {
		error = cb(&client->meat, arg);
		if (error)
			break;
	}

	read_unlock(&rlock, &wlock, &rcounter);

	return error;
}

void
clients_db_destroy(void)
{
	struct hashable_client *node, *tmp;

	sem_wait(&wlock);

	HASH_ITER(hh, table, node, tmp) {
		HASH_DEL(table, node);
		free(node);
	}

	sem_post(&wlock);

	sem_destroy(&wlock);
	sem_destroy(&rlock);
}
