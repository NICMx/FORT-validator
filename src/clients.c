#include "clients.h"

#include <pthread.h>
#include "common.h"
#include "log.h"
#include "data_structure/uthash.h"

/*
 * TODO uthash panics on memory allocations...
 * http://troydhanson.github.io/uthash/userguide.html#_out_of_memory
 */

#define SADDR_IN(addr) ((struct sockaddr_in *) addr)
#define SADDR_IN6(addr) ((struct sockaddr_in6 *) addr)

struct hashable_client {
	struct client meat;
	UT_hash_handle hh;
};

/** Hash table of clients */
static struct hashable_client *table;
/** Read/write lock, which protects @table and its inhabitants. */
static pthread_rwlock_t lock;
/** Serial number from which deltas must be stored */
static uint32_t min_serial;

int
clients_db_init(void)
{
	int error;

	table = NULL;
	error = pthread_rwlock_init(&lock, NULL);
	if (error)
		return pr_errno(error, "pthread_rwlock_init() errored");
	min_serial = 0;
	return 0;
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

	rwlock_write_lock(&lock);

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

	rwlock_unlock(&lock);

	if (new_client != NULL)
		free(new_client);

	return error;
}

void
clients_update_serial(int fd, uint32_t serial)
{
	struct hashable_client *cur_client;

	rwlock_write_lock(&lock);
	HASH_FIND_INT(table, &fd, cur_client);
	if (cur_client == NULL)
		goto unlock;

	cur_client->meat.serial_number = serial;

unlock:
	rwlock_unlock(&lock);
}

uint32_t
clients_get_min_serial(void)
{
	struct hashable_client *current, *ptr;
	uint32_t result;

	rwlock_write_lock(&lock);
	if (HASH_COUNT(table) == 0)
		goto unlock;

	min_serial = table->meat.serial_number;
	HASH_ITER(hh, table, current, ptr)
		if (current->meat.serial_number < min_serial)
			min_serial = current->meat.serial_number;

unlock:
	result = min_serial;
	rwlock_unlock(&lock);

	return result;
}

void
clients_forget(int fd)
{
	struct hashable_client *client;

	rwlock_write_lock(&lock);

	HASH_FIND_INT(table, &fd, client);
	if (client != NULL) {
		HASH_DEL(table, client);
		free(client);
	}

	rwlock_unlock(&lock);
}

int
clients_foreach(clients_foreach_cb cb, void *arg)
{
	struct hashable_client *client;
	int error;

	error = rwlock_read_lock(&lock);
	if (error)
		return error;

	for (client = table; client != NULL; client = client->hh.next) {
		error = cb(&client->meat, arg);
		if (error)
			break;
	}

	rwlock_unlock(&lock);

	return error;
}

void
clients_db_destroy(void)
{
	struct hashable_client *node, *tmp;

	HASH_ITER(hh, table, node, tmp) {
		HASH_DEL(table, node);
		free(node);
	}

	pthread_rwlock_destroy(&lock); /* Nothing to do with error code */
}
