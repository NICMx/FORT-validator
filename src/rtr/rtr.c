#include "rtr.h"

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../common.h"
#include "pdu.h"

static int
bind_server_socket6(int socket, struct sockaddr_in6 *host_addr, __u16 port)
{
	int err;
	struct sockaddr_in6 address;

	memset(&address, 0, sizeof(address));
	address.sin6_family = AF_INET6;
	address.sin6_addr.__in6_u = host_addr->sin6_addr.__in6_u;
	address.sin6_port = htons(port);

	if (bind(socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
		err = errno;
		warn("Could not bind the address. errno : %d", -abs(err));
		return -abs(err);
	}

	return 0;
}

static int
bind_server_socket4(int socket, struct sockaddr_in *host_addr, __u16 port)
{
	int err;
	struct sockaddr_in address;

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = host_addr->sin_addr.s_addr;
	address.sin_port = htons(port);

	if (bind(socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
		err = errno;
		warn("Could not bind the address. errno : %d", -abs(err));
		return -abs(err);
	}

	return 0;
}

static void
log_binded_server_socket(struct addrinfo *host, __u16 port)
{
	char hostaddr[INET6_ADDRSTRLEN];
	struct sockaddr_in *h4;
	struct sockaddr_in6 *h6;

	memset(&hostaddr, 0, INET6_ADDRSTRLEN);
	switch(host->ai_family) {
		case AF_INET:
			h4 = (struct sockaddr_in *) host->ai_addr;
			inet_ntop(host->ai_family, &h4->sin_addr, (char * restrict) &hostaddr, sizeof(hostaddr));
			pr_debug("Listening %s#%d", hostaddr, port);
			break;
		case AF_INET6:
			h6 = (struct sockaddr_in6 *) host->ai_addr;
			inet_ntop(host->ai_family, &h6->sin6_addr, (char * restrict) &hostaddr, sizeof(hostaddr));
			pr_debug("Listening [%s]#%d", hostaddr, port);
			break;
		default:
			warn("Unknown AI_FAMILY type: %d", host->ai_family);
	}
}

/*
 * Creates the socket that will stay put and wait for new connections started
 * from the clients.
 */
static int
create_server_socket(struct addrinfo *server_addr, __u16 port)
{
	int fd; /* "file descriptor" */
	struct addrinfo *tmp;
	int err;

	if (server_addr == NULL){
		warn("A server address must be present to bind a socket");
		return -EINVAL;
	}

	for (tmp = server_addr; tmp != NULL; tmp = tmp->ai_next) {
		err = 0;
		fd = socket(tmp->ai_family, SOCK_STREAM, 0);
		if (fd < 0) {
			err = errno;
			err = -abs(err);
			warn("Error opening socket. errno : %d", err);
			continue;
		}

		switch(tmp->ai_family) {
		case AF_INET:
			err = bind_server_socket4(fd, (struct sockaddr_in *) tmp->ai_addr, port);
			if (err)
				close(fd);
			break;
		case AF_INET6:
			err = bind_server_socket6(fd, (struct sockaddr_in6 *) tmp->ai_addr, port);
			if (err)
				close(fd);
			break;
		default:
			close(fd);
			warn("Can't handle ai_family type: %d", tmp->ai_family);
			err = -EINVAL;
		}

		if (!err) {
			log_binded_server_socket(tmp, port);
			break;
		}
	}

	if (err)
		return err;

	return fd;
}

/*
 * Arguments that the server socket thread will send to the client socket
 * threads whenever it creates them.
 */
struct thread_param {
	int	client_fd;
};

enum verdict {
	/* No errors; continue happily. */
	VERDICT_SUCCESS,
	/* A temporal error just happened. Try again. */
	VERDICT_RETRY,
	/* "Stop whatever you're doing and return." */
	VERDICT_EXIT,
};

/*
 * Converts an error code to a verdict.
 * The error code is assumed to have been spewed by the `accept()` function.
 */
static enum verdict
handle_accept_result(int client_fd, int err)
{
	if (client_fd == 0)
		return VERDICT_SUCCESS;

	/*
	 * Note: I can't just use a single nice switch because EAGAIN and
	 * EWOULDBLOCK are the same value in at least one supported system
	 * (Linux).
	 */

	/*
	 * TODO this `if` is a Linux quirk and should probably not exist in the
	 * BSDs. See `man 2 accept`.
	 */
	if (err == ENETDOWN || err == EPROTO || err == ENOPROTOOPT
	    || err == EHOSTDOWN || err == ENONET || err == EHOSTUNREACH
	    || err == EOPNOTSUPP || err == ENETUNREACH)
		return VERDICT_RETRY;

	if (err == EAGAIN || err == EWOULDBLOCK)
		return VERDICT_RETRY;

	errno = err;
	warn("Connection acceptor thread interrupted");
	return VERDICT_EXIT;
}

/*
 * The client socket threads' entry routine.
 *
 * Please remember that this function needs to always release @param_void before
 * returning.
 */
static void *
client_thread_cb(void *param_void)
{
	struct thread_param param;
	struct pdu_metadata const *meta;
	void *pdu;
	int err;

	memcpy(&param, param_void, sizeof(param));
	free(param_void);

	while (true) { /* For each PDU... */
		err = pdu_load(param.client_fd, &pdu, &meta);
		if (err)
			return NULL;

		err = meta->handle(&pdu);
		meta->destructor(pdu);
		if (err)
			return NULL;
	}

	return NULL; /* Unreachable. */
}

/*
 * Waits for client connections and spawns threads to handle them.
 */
static int
handle_client_connections(int server_fd)
{
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t sizeof_client_addr;
	struct thread_param *arg;
	pthread_t thread;

	listen(server_fd, 5);

	sizeof_client_addr = sizeof(client_addr);

	do {
		client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
		    &sizeof_client_addr);
		switch (handle_accept_result(client_fd, errno)) {
		case VERDICT_SUCCESS:
			break;
		case VERDICT_RETRY:
			continue;
		case VERDICT_EXIT:
			return 0;
		}

		/*
		 * Note: My gut says that errors from now on (even the unknown
		 * ones) should be treated as temporary; maybe the next accept()
		 * will work.
		 * So don't interrupt the thread when this happens.
		 */

		arg = malloc(sizeof(struct thread_param));
		if (!arg) {
			warnx("Thread parameter allocation failure");
			continue;
		}
		arg->client_fd = client_fd;

		errno = pthread_create(&thread, NULL, client_thread_cb, arg);
		if (errno) {
			warn("Could not spawn the client's thread");
			free(arg);
			close(client_fd);
			continue;
		}

		/* BTW: The thread will be responsible for releasing @arg. */
		pthread_detach(thread);

	} while (true);

	return 0; /* Unreachable. */
}

/*
 * Starts the server, using the current thread to listen for RTR client
 * requests.
 *
 * This function blocks.
 */
int
rtr_listen(struct addrinfo *server_addr, __u16 port)
{
	int server_fd; /* "file descriptor" */

	server_fd = create_server_socket(server_addr, port);
	if (server_fd < 0)
		return server_fd;

	return handle_client_connections(server_fd);
}
