#include "clients.h"

#include "array_list.h"

#define SADDR_IN(addr) ((struct sockaddr_in *)addr)
#define SADDR_IN6(addr) ((struct sockaddr_in6 *)addr)

ARRAY_LIST(clientsdb, struct client)

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

static struct client
*get_client(struct sockaddr_storage *addr, u_int8_t rtr_version)
{
	struct client *ptr;

	ARRAYLIST_FOREACH(clients_db, ptr)
		if (ptr->rtr_version == rtr_version &&
		    ptr->sin_family == addr->ss_family) {
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
create_client(int fd, struct sockaddr_storage *addr, u_int8_t rtr_version,
    time_t ttl)
{
	struct client *client;

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
	client->expiration = time(NULL) + ttl;

	return clients_db_add_client(client);
}

int
update_client(int fd, struct sockaddr_storage *addr, u_int8_t rtr_version,
    time_t ttl)
{
	struct client *client;
	client = get_client(addr, rtr_version);

	if (client == NULL)
		return create_client(fd, addr, rtr_version, ttl);
	client->expiration = time(NULL) + ttl;
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
