#include "clients.h"

#include "array_list.h"
#include "common.h"

#define SADDR_IN(addr) ((struct sockaddr_in *)addr)
#define SADDR_IN6(addr) ((struct sockaddr_in6 *)addr)

ARRAY_LIST(clientsdb, struct client)

struct clientsdb clients_db;

/* Read and Write locks */
sem_t rlock, wlock;

/* Readers counter */
unsigned int rcounter;

int
clients_db_init(void)
{
	int error;

	error = clientsdb_init(&clients_db);
	if (error)
		warnx( "Clients DB couldn't be initialized");

	sem_init(&rlock, 0, 1);
	sem_init(&wlock, 0, 1);
	rcounter = 0;

	return error;
}

static struct client *
get_client(struct sockaddr_storage *addr)
{
	struct client *ptr;

	read_lock(&rlock, &wlock, &rcounter);
	ARRAYLIST_FOREACH(&clients_db, ptr)
		if (ptr->sin_family == addr->ss_family) {
			if (ptr->sin_family == AF_INET) {
				if (ptr->sin_addr.s_addr ==
				    SADDR_IN(addr)->sin_addr.s_addr &&
				    ptr->sin_port ==
				    SADDR_IN(addr)->sin_port) {
					read_unlock(&rlock, &wlock, &rcounter);
					return ptr;
				}
			} else if (ptr->sin_family == AF_INET6)
				if (IN6_ARE_ADDR_EQUAL(
				    ptr->sin6_addr.s6_addr32,
				    SADDR_IN6(addr)->sin6_addr.s6_addr32) &&
				    ptr->sin_port ==
				    SADDR_IN6(addr)->sin6_port) {
					read_unlock(&rlock, &wlock, &rcounter);
					return ptr;
				}
		}
	read_unlock(&rlock, &wlock, &rcounter);
	return NULL;
}

static int
create_client(int fd, struct sockaddr_storage *addr, u_int8_t rtr_version)
{
	struct client client;
	int error;

	client.fd = fd;
	client.sin_family = addr->ss_family;
	if (addr->ss_family == AF_INET) {
		client.sin_addr = SADDR_IN(addr)->sin_addr;
		client.sin_port = SADDR_IN(addr)->sin_port;
	} else if (addr->ss_family == AF_INET6) {
		client.sin6_addr = SADDR_IN6(addr)->sin6_addr;
		client.sin_port = SADDR_IN6(addr)->sin6_port;
	}
	client.rtr_version = rtr_version;

	sem_wait(&wlock);
	error = clientsdb_add(&clients_db, &client);
	sem_post(&wlock);

	return error;
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
	 * Isn't ready to handle distinct version on clients reconnection, but
	 * for now there's no problem since only RTR v0 is supported.
	 */
	if (client->rtr_version != rtr_version)
		return -EINVAL;

	client->fd = fd;
	return 0;
}

size_t
client_list(struct client **clients)
{
	size_t len;

	read_lock(&rlock, &wlock, &rcounter);
	*clients = clients_db.array;
	len = clients_db.len;
	read_unlock(&rlock, &wlock, &rcounter);

	return len;
}

static void
client_destroy(struct client *client)
{
	/* Didn't allocate something, so do nothing */
}

void
clients_db_destroy(void)
{
	sem_wait(&wlock);
	clientsdb_cleanup(&clients_db, client_destroy);
	sem_post(&wlock);

	sem_destroy(&wlock);
	sem_destroy(&rlock);
}
