#include "clients.h"

#include <sys/queue.h>
#include "common.h"
#include "log.h"
#include "data_structure/uthash_nonfatal.h"
#include "rtr/pdu.h"

struct hashable_client {
	struct client meat;
	UT_hash_handle hh;
};

struct thread_node {
	pthread_t tid;
	SLIST_ENTRY(thread_node) next;
};

/*
 * Thread ids are stored apart so that the caller can join each thread at the
 * end.
 *
 * The join should be made when the db is cleared, so the main process should
 * do it.
 */
SLIST_HEAD(thread_list, thread_node);

/** Hash table of clients and threads */
static struct clients_table {
	struct hashable_client *clients;
	struct thread_list threads;
} db;

/** Read/write lock, which protects @table and its inhabitants. */
static pthread_rwlock_t lock;

int
clients_db_init(void)
{
	int error;

	db.clients = NULL;
	SLIST_INIT(&db.threads);

	error = pthread_rwlock_init(&lock, NULL);
	if (error)
		return pr_errno(error, "pthread_rwlock_init() errored");
	return 0;
}

static struct hashable_client *
create_client(int fd, struct sockaddr_storage addr, pthread_t tid)
{
	struct hashable_client *client;

	client = malloc(sizeof(struct hashable_client));
	if (client == NULL)
		return NULL;
	/* Needed by uthash */
	memset(client, 0, sizeof(struct hashable_client));

	client->meat.fd = fd;
	client->meat.serial_number_set = false;
	client->meat.addr = addr;

	return client;
}

/*
 * If the client whose file descriptor is @fd isn't already stored, store it.
 */
int
clients_add(int fd, struct sockaddr_storage addr, pthread_t tid)
{
	struct hashable_client *new_client;
	struct hashable_client *old_client;
	struct thread_node *new_thread;

	new_client = create_client(fd, addr, tid);
	if (new_client == NULL)
		return pr_enomem();

	new_thread = malloc(sizeof(struct thread_node));
	if (new_thread == NULL) {
		free(new_client);
		return pr_enomem();
	}
	new_thread->tid = tid;

	rwlock_write_lock(&lock);

	errno = 0;
	HASH_REPLACE(hh, db.clients, meat.fd, sizeof(new_client->meat.fd),
	    new_client, old_client);
	if (errno) {
		rwlock_unlock(&lock);
		free(new_client);
		return -pr_errno(errno, "Client couldn't be stored");
	}
	if (old_client != NULL)
		free(old_client);

	SLIST_INSERT_HEAD(&db.threads, new_thread, next);

	rwlock_unlock(&lock);

	return 0;
}

int
clients_get_addr(int fd, struct sockaddr_storage *addr)
{
	struct hashable_client *client;
	int result;

	result = -ENOENT;
	rwlock_write_lock(&lock);

	HASH_FIND_INT(db.clients, &fd, client);
	if (client != NULL) {
		*addr = client->meat.addr;
		result = 0;
	}

	rwlock_unlock(&lock);

	return result;
}

void
clients_update_serial(int fd, serial_t serial)
{
	struct hashable_client *cur_client;

	rwlock_write_lock(&lock);
	HASH_FIND_INT(db.clients, &fd, cur_client);
	if (cur_client == NULL)
		goto unlock;

	cur_client->meat.serial_number = serial;
	cur_client->meat.serial_number_set = true;

unlock:
	rwlock_unlock(&lock);
}

int
clients_get_min_serial(serial_t *result)
{
	struct hashable_client *current, *tmp;
	int retval;

	retval = -ENOENT;
	rwlock_read_lock(&lock);
	if (HASH_COUNT(db.clients) == 0)
		goto unlock;

	HASH_ITER(hh, db.clients, current, tmp) {
		if (!current->meat.serial_number_set)
			continue;
		if (retval) {
			*result = current->meat.serial_number;
			retval = 0;
		} else if (current->meat.serial_number < *result)
			*result = current->meat.serial_number;
	}

unlock:
	rwlock_unlock(&lock);
	return retval;
}

void
clients_forget(int fd)
{
	struct hashable_client *client;

	rwlock_write_lock(&lock);

	HASH_FIND_INT(db.clients, &fd, client);
	if (client != NULL) {
		HASH_DEL(db.clients, client);
		free(client);
	}

	rwlock_unlock(&lock);
}

int
clients_foreach(clients_foreach_cb cb, void *arg)
{
	struct hashable_client *client, *tmp;
	int error;

	error = rwlock_read_lock(&lock);
	if (error)
		return error;

	HASH_ITER(hh, db.clients, client, tmp) {
		error = cb(&client->meat, arg);
		if (error)
			break;
	}

	rwlock_unlock(&lock);

	return error;
}

/*
 * Destroy the clients DB, the @join_thread_cb will be made for each thread
 * that was started by the parent process (@arg will be sent at that call).
 */
void
clients_db_destroy(join_thread_cb cb, void *arg)
{
	struct hashable_client *node, *tmp;
	struct thread_node *thread;

	HASH_ITER(hh, db.clients, node, tmp) {
		HASH_DEL(db.clients, node);
		free(node);
	}

	while (!SLIST_EMPTY(&db.threads)) {
		thread = SLIST_FIRST(&db.threads);
		SLIST_REMOVE_HEAD(&db.threads, next);

		/* Not much to do on failure */
		cb(thread->tid, arg);
		free(thread);
	}

	pthread_rwlock_destroy(&lock); /* Nothing to do with error code */
}
