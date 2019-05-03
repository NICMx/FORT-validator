#include "rtr.h"

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include "config.h"
#include "clients.h"
#include "log.h"
#include "updates_daemon.h"
#include "rtr/err_pdu.h"
#include "rtr/pdu.h"

/* TODO (next iteration) Support both RTR v0 and v1 */
#define RTR_VERSION_SUPPORTED	RTR_V0

/* TODO (urgent) this needs to be atomic */
volatile bool loop;

/*
 * Arguments that the server socket thread will send to the client
 * socket threads whenever it creates them.
 */
struct thread_param {
	int client_fd;
	struct sockaddr_storage client_addr;
};

struct thread_node {
	pthread_t tid;
	struct thread_param params;
	SLIST_ENTRY(thread_node) next;
};

SLIST_HEAD(thread_list, thread_node) threads;

static int
init_addrinfo(struct addrinfo **result)
{
	char const *hostname;
	char const *service;
	struct addrinfo hints;
	int error;

	memset(&hints, 0 , sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	/* hints.ai_socktype = SOCK_DGRAM; */
	hints.ai_flags |= AI_PASSIVE;

	hostname = config_get_server_address();
	service = config_get_server_port();

	error = getaddrinfo(hostname, service, &hints, result);
	if (error) {
		pr_err("Could not infer a bindable address out of address '%s' and port '%s': %s",
		    (hostname != NULL) ? hostname : "any", service,
		    gai_strerror(error));
		return error;
	}

	return 0;
}


/*
 * Creates the socket that will stay put and wait for new connections started
 * from the clients.
 */
static int
create_server_socket(int *result)
{
	struct addrinfo *addrs;
	struct addrinfo *addr;
	int fd; /* "file descriptor" */
	int error;

	*result = 0; /* Shuts up gcc */

	error = init_addrinfo(&addrs);
	if (error)
		return error;

	for (addr = addrs; addr != NULL; addr = addr->ai_next) {
		printf(
		    "Attempting to bind socket to address '%s', port '%s'.\n",
		    (addr->ai_canonname != NULL) ? addr->ai_canonname : "any",
		    config_get_server_port());

		fd = socket(addr->ai_family, SOCK_STREAM, 0);
		if (fd < 0) {
			pr_errno(errno, "socket() failed");
			continue;
		}

		if (bind(fd, addr->ai_addr, addr->ai_addrlen) < 0) {
			pr_errno(errno, "bind() failed");
			continue;
		}

		printf("Success.\n");
		freeaddrinfo(addrs);
		*result = fd;
		return 0; /* Happy path */
	}

	freeaddrinfo(addrs);
	return pr_err("None of the addrinfo candidates could be bound.");
}

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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wlogical-op"
	if (err == EAGAIN || err == EWOULDBLOCK)
		return VERDICT_RETRY;
#pragma GCC diagnostic pop

	errno = err;
	pr_warn("Connection acceptor thread interrupted");
	return VERDICT_EXIT;
}

static void *
end_client(int client_fd, const struct pdu_metadata *meta, void *pdu)
{
	if (meta != NULL && pdu != NULL)
		meta->destructor(pdu);
	clients_forget(client_fd);
	return NULL;
}

/*
 * The client socket threads' entry routine.
 */
static void *
client_thread_cb(void *param_void)
{
	struct thread_param *param = param_void;
	struct pdu_metadata const *meta;
	void *pdu;
	int err;
	uint8_t rtr_version;

	while (loop) { /* For each PDU... */
		err = pdu_load(param->client_fd, &pdu, &meta, &rtr_version);
		if (err)
			return end_client(param->client_fd, NULL, NULL);

		/* Protocol Version Negotiation */
		if (rtr_version != RTR_VERSION_SUPPORTED) {
			err_pdu_send(param->client_fd, RTR_VERSION_SUPPORTED,
			    ERR_PDU_UNSUP_PROTO_VERSION,
			    (struct pdu_header *) pdu, NULL);
			return end_client(param->client_fd, meta, pdu);
		}
		/* RTR Version ready, now update client */
		err = clients_add(param->client_fd, &param->client_addr,
		    rtr_version);
		if (err) {
			if (err == -ERTR_VERSION_MISMATCH) {
				err_pdu_send(param->client_fd, rtr_version,
				    (rtr_version == RTR_V0
				    ? ERR_PDU_UNSUP_PROTO_VERSION
				    : ERR_PDU_UNEXPECTED_PROTO_VERSION),
				    (struct pdu_header *) pdu, NULL);
			}
			return end_client(param->client_fd, meta, pdu);
		}

		err = meta->handle(param->client_fd, pdu);
		meta->destructor(pdu);
		if (err)
			return end_client(param->client_fd, NULL, NULL);
	}

	return NULL; /* Unreachable. */
}

/*
 * Waits for client connections and spawns threads to handle them.
 */
static int
handle_client_connections(int server_fd)
{
	struct sockaddr_storage client_addr;
	struct thread_node *new_thread;
	socklen_t sizeof_client_addr;
	int client_fd;

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
		 * ones) should be treated as temporary; maybe the next
		 * accept() will work.
		 * So don't interrupt the thread when this happens.
		 */

		new_thread = malloc(sizeof(struct thread_node));
		if (new_thread == NULL) {
			pr_err("Couldn't create thread struct");
			close(client_fd);
			continue;
		}

		new_thread->params.client_fd = client_fd;
		new_thread->params.client_addr = client_addr;

		errno = pthread_create(&new_thread->tid, NULL,
		    client_thread_cb, &new_thread->params);
		if (errno) {
			pr_errno(errno, "Could not spawn the client's thread");
			free(new_thread);
			close(client_fd);
			continue;
		}

		SLIST_INSERT_HEAD(&threads, new_thread, next);

	} while (true);

	return 0; /* Unreachable. */
}

static void
signal_handler(int signal, siginfo_t *info, void *param)
{
	/* Empty handler */
}

static int
init_signal_handler(void)
{
	struct sigaction act;
	int error;

	memset(&act, 0, sizeof act);
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = signal_handler;

	/* TODO is this really legal? @act might need to be global. */
	error = sigaction(SIGINT, &act, NULL);
	if (error) {
		pr_errno(errno, "Error initializing signal handler");
		error = -errno;
	}
	return error;
}

/* Terminates client threads as gracefully as I know how to. */
static void
wait_threads(void)
{
	struct thread_node *ptr;

	loop = false;
	while (!SLIST_EMPTY(&threads)) {
		ptr = SLIST_FIRST(&threads);
		SLIST_REMOVE_HEAD(&threads, next);
		/*
		 * If the close fails, the thread might still be using the
		 * thread_param variables, so leak instead.
		 */
		if (close_thread(ptr->tid, "Client") == 0)
			free(ptr);
	}
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
	int error;

	error = create_server_socket(&server_fd);
	if (error)
		return error;

	/* Server ready, start updates thread */
	error = updates_daemon_start();
	if (error)
		goto revert_server_socket;

	/* Init global vars */
	loop = true;
	SLIST_INIT(&threads);

	error = init_signal_handler();
	if (error)
		goto revert_updates_daemon;

	error = handle_client_connections(server_fd);

	wait_threads();
revert_updates_daemon:
	updates_daemon_destroy();
revert_server_socket:
	close(server_fd);
	return error;
}