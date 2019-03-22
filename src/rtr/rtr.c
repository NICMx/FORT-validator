#include "rtr.h"

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "clients.h"
#include "configuration.h"
#include "err_pdu.h"
#include "pdu.h"

/* TODO Support both RTR v0 an v1 */
#define RTR_VERSION_SUPPORTED	RTR_V0

/*
 * Creates the socket that will stay put and wait for new connections started
 * from the clients.
 */
static int
create_server_socket(void)
{
	struct addrinfo const *addr;
	int fd; /* "file descriptor" */

	addr = config_get_server_addrinfo();
	for (; addr != NULL; addr = addr->ai_next) {
		printf("Attempting to bind socket to address '%s', port '%s'.\n",
		    (addr->ai_canonname != NULL) ? addr->ai_canonname : "any",
		    config_get_server_port());

		fd = socket(addr->ai_family, SOCK_STREAM, 0);
		if (fd < 0) {
			warn("socket() failed");
			continue;
		}

		if (bind(fd, addr->ai_addr, addr->ai_addrlen) < 0) {
			warn("bind() failed");
			continue;
		}

		printf("Success.\n");
		return fd; /* Happy path */
	}

	warnx("None of the addrinfo candidates could be bound.");
	return -EINVAL;
}

/*
 * Arguments that the server socket thread will send to the client socket
 * threads whenever it creates them.
 */
struct thread_param {
	int	client_fd;
	struct sockaddr_storage client_addr;
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
	if (client_fd >= 0)
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
 * Please remember that this function needs to always release @param_void
 * before returning.
 */
static void *
client_thread_cb(void *param_void)
{
	struct thread_param param;
	struct pdu_metadata const *meta;
	void *pdu;
	int err;
	u_int8_t rtr_version;

	memcpy(&param, param_void, sizeof(param));
	free(param_void); /* Ha. */

	while (true) { /* For each PDU... */
		err = pdu_load(param.client_fd, &pdu, &meta, &rtr_version);
		if (err)
			return NULL;

		/* Protocol Version Negotiation */
		if (rtr_version != RTR_VERSION_SUPPORTED) {
			err_pdu_send(param.client_fd, RTR_VERSION_SUPPORTED,
			    ERR_PDU_UNSUP_PROTO_VERSION,
			    (struct pdu_header *) pdu, NULL);
			meta->destructor(pdu);
			return NULL;
		}
		/* RTR Version ready, now update client */
		err = update_client(param.client_fd, &param.client_addr,
		    rtr_version);
		if (err) {
			if (err == -EINVAL) {
				err_pdu_send(param.client_fd, rtr_version,
				    (rtr_version == RTR_V0
				    ? ERR_PDU_UNSUP_PROTO_VERSION
				    : ERR_PDU_UNEXPECTED_PROTO_VERSION),
				    (struct pdu_header *) pdu, NULL);
			}
			meta->destructor(pdu);
			return NULL;
		}

		err = meta->handle(param.client_fd, pdu);
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
	struct sockaddr_storage client_addr;
	socklen_t sizeof_client_addr;
	struct thread_param *arg;
	pthread_t thread;

	listen(server_fd, config_get_server_queue());

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
		if (arg == NULL) {
			warn("Thread parameter allocation failure");
			continue;
		}
		arg->client_fd = client_fd;
		arg->client_addr = client_addr;

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
rtr_listen(void)
{
	int server_fd; /* "file descriptor" */

	server_fd = create_server_socket();
	if (server_fd < 0)
		return server_fd;

	return handle_client_connections(server_fd);
}
