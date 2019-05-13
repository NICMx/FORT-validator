#include "clients.h"

#include <pthread.h>
#include "common.h"
#include "log.h"
#include "data_structure/uthash.h"
#include "rtr/pdu.h"

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
static serial_t min_serial;

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
create_client(struct rtr_client *client, struct hashable_client **result)
{
	struct hashable_client *node;

	node = malloc(sizeof(struct hashable_client));
	if (node == NULL)
		return pr_enomem();

	node->meat.fd = client->fd;
	node->meat.serial_number_set = false;

	*result = node;
	return 0;
}

/*
 * If the client whose file descriptor is @fd isn't already stored, store it.
 */
int
clients_add(struct rtr_client *client)
{
	struct hashable_client *new_client = NULL;
	struct hashable_client *old_client;
	int error;

	error = create_client(client, &new_client);
	if (error)
		return error;

	rwlock_write_lock(&lock);

	HASH_FIND_INT(table, &client->fd, old_client);
	if (old_client == NULL) {
		HASH_ADD_INT(table, meat.fd, new_client);
		new_client = NULL;
	}

	rwlock_unlock(&lock);

	if (new_client != NULL)
		free(new_client);

	return 0;
}

void
clients_update_serial(int fd, serial_t serial)
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

serial_t
clients_get_min_serial(void)
{
	struct hashable_client *current, *ptr;
	serial_t result;

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
