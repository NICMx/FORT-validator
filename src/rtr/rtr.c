#include "rtr.h"

#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common.h"
#include "../types.h"
#include "pdu.h"

/*
 * Creates the socket that will stay put and wait for new connections started
 * from the clients.
 */
static int
create_server_socket(struct in_addr *server_addr, __u16 port)
{
	int fd; /* "file descriptor" */
	struct sockaddr_in address;
	int err;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		err = errno;
		warn("Error opening socket");
		return -abs(err);
	}

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = server_addr->s_addr;
	address.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		err = errno;
		warn("Could not bind the address");
		close(fd);
		return -abs(err);
	}

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
rtr_listen(struct in_addr *server_addr, __u16 port)
{
	int server_fd; /* "file descriptor" */

	server_fd = create_server_socket(server_addr, port);
	if (server_fd < 0)
		return server_fd;

	return handle_client_connections(server_fd);
}
