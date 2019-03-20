#include "clients.h"

#include "array_list.h"

#define SADDR_IN(addr) ((struct sockaddr_in *)addr)
#define SADDR_IN6(addr) ((struct sockaddr_in6 *)addr)

ARRAY_LIST(clientsdb, struct client)

/* TODO (review) Does not need to live in the heap */
struct clientsdb *clients_db;

int
clients_db_init(void)
{
	int error;

	clients_db = malloc(sizeof(struct clientsdb));
	if (clients_db == NULL) {
		err(-ENOMEM, "Clients DB couldn't be allocated");
		return -ENOMEM;
	}
	error = clientsdb_init(clients_db);
	if (error)
		err(error, "Clients DB couldn't be initialized");

	return error;
}

static int
clients_db_add_client(struct client *client)
{
	return clientsdb_add(clients_db, client);
}

static struct client *
get_client(struct sockaddr_storage *addr)
{
	struct client *ptr;

	ARRAYLIST_FOREACH(clients_db, ptr)
		if (ptr->sin_family == addr->ss_family) {
			if (ptr->sin_family == AF_INET) {
				if (ptr->sin_addr.s_addr == SADDR_IN(addr)->sin_addr.s_addr &&
				    ptr->sin_port == SADDR_IN(addr)->sin_port)
					return ptr;
			} else if (ptr->sin_family == AF_INET6)
				if (IN6_ARE_ADDR_EQUAL(ptr->sin6_addr.s6_addr32, SADDR_IN6(addr)->sin6_addr.s6_addr32) &&
				    ptr->sin_port == SADDR_IN6(addr)->sin6_port)
					return ptr;
		}

	return NULL;
}

static int
create_client(int fd, struct sockaddr_storage *addr, u_int8_t rtr_version)
{
	struct client *client;

	/* TODO (review) `client` should be in the stack. */
	client = malloc(sizeof(struct client));
	if (client == NULL) {
		err(-ENOMEM, "Couldn't allocate client");
		return -ENOMEM;
	}

	client->fd = fd;
	client->sin_family = addr->ss_family;
	if (addr->ss_family == AF_INET) {
		client->sin_addr = SADDR_IN(addr)->sin_addr;
		client->sin_port = SADDR_IN(addr)->sin_port;
	} else if (addr->ss_family == AF_INET6) {
		client->sin6_addr = SADDR_IN6(addr)->sin6_addr;
		client->sin_port = SADDR_IN6(addr)->sin6_port;
	}
	client->rtr_version = rtr_version;

	return clients_db_add_client(client);
}

/*
 * If the ADDR isn't already stored, store it; otherwise update its file
 * descriptor.
 *
 * Return the creation/update result.
 *
 * Code error -EINVAL will be returned when a client exists but its RTR version
 * isn't the same as in the DB.
 */
int
update_client(int fd, struct sockaddr_storage *addr, u_int8_t rtr_version)
{
	struct client *client;
	client = get_client(addr);

	if (client == NULL)
		return create_client(fd, addr, rtr_version);

	/*
	 * TODO (review) Your margin seems to be misconfigured; you're violating
	 * the line width often.
	 *
	 * Line width is 80 characters and tabs are 8.
	 *
	 * `Window > Preferences > C/C++ > Code Style > Formatter > New... > Ok`
	 * 	`Indentation > Tab size`
	 * 	`Line Wrapping > Maximum line width`
	 */
	/*
	 * Isn't ready to handle distinct version on clients reconnection, but for
	 * now there's no problem since only 1 RTR version is supported (RVR v0).
	 */
	if (client->rtr_version != rtr_version)
		return -EINVAL;

	client->fd = fd;
	return 0;
}

size_t
client_list(struct client **clients)
{
	*clients = clients_db->array;
	return clients_db->len;
}

static void
client_destroy(struct client *client)
{
	free(client);
}

void
clients_db_destroy(void)
{
	clientsdb_cleanup(clients_db, client_destroy);
	free(clients_db);
}
