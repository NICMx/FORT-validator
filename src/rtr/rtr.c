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

struct sigaction act;

struct thread_node {
	pthread_t tid;
	struct rtr_client client;
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

static void
clean_request(struct rtr_request *request, const struct pdu_metadata *meta)
{
	free(request->bytes);
	meta->destructor(request->pdu);
}

static void *
end_client(struct rtr_client *client)
{
	/*
	 * TODO It'd probably be a good idea to print the client's address in
	 * this message.
	 */
	if (close(client->fd) != 0)
		pr_errno(errno, "close() failed on client socket");

	clients_forget(client->fd);
	return NULL;
}

/*
 * The client socket threads' entry routine.
 */
static void *
client_thread_cb(void *arg)
{
	struct rtr_client *client = arg;
	struct pdu_metadata const *meta;
	struct rtr_request request;
	int error;

	while (true) { /* For each PDU... */
		error = pdu_load(client->fd, &request, &meta);
		if (error)
			break;

		error = meta->handle(client->fd, &request);
		clean_request(&request, meta);
		if (error)
			break;
	}

	return end_client(client);
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
	int error;

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

		/*
		 * TODO this is more complicated than it needs to be.
		 * We have a client hash table and a thread linked list.
		 * These two contain essentially the same entries. It's
		 * redundant.
		 */

		new_thread = malloc(sizeof(struct thread_node));
		if (new_thread == NULL) {
			/* No error response PDU on memory allocation. */
			pr_err("Couldn't create thread struct");
			close(client_fd);
			continue;
		}

		new_thread->client.fd = client_fd;
		new_thread->client.addr = client_addr;

		error = clients_add(&new_thread->client);
		if (error) {
			/*
			 * Presently, clients_add() can only fail due to alloc
			 * failure. No error report PDU.
			 */
			free(new_thread);
			close(client_fd);
			continue;
		}

		error = pthread_create(&new_thread->tid, NULL,
		    client_thread_cb, &new_thread->client);
		if (error && error != EAGAIN)
			err_pdu_send_internal_error(client_fd);
		if (error) {
			pr_errno(error, "Could not spawn the client's thread");
			clients_forget(client_fd);
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
	int error;

	memset(&act, 0, sizeof act);
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = signal_handler;

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
