#include "rtr.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
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
#include "internal_pool.h"
#include "log.h"
#include "validation_run.h"
#include "rtr/err_pdu.h"
#include "rtr/pdu.h"
#include "rtr/db/vrps.h"
#include "thread/thread_pool.h"

/* Constant messages regarding a client status */
#define CL_ACCEPTED   "accepted"
#define CL_CLOSED     "closed"
#define CL_TERMINATED "terminated"
#define CL_REJECTED   "rejected"

/* Parameters for each thread that handles client connections */
struct thread_param {
	int fd;
	struct sockaddr_storage addr;
};

/* Parameters for each file descriptor that binds to a server address/socket */
struct fd_node {
	int id;
	SLIST_ENTRY(fd_node) next;
};

/* List of server sockets */
SLIST_HEAD(server_fds, fd_node);

/* Does the server needs to be stopped? */
static volatile bool server_stop;

/* Parameters for the RTR server task */
struct rtr_task_param {
	struct server_fds *fds;
	struct thread_pool *pool;
};

static int
init_addrinfo(char const *hostname, char const *service,
    struct addrinfo **result)
{
	char *tmp;
	struct addrinfo hints;
	unsigned long parsed, port;
	int error;

	memset(&hints, 0 , sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	/* hints.ai_socktype = SOCK_DGRAM; */
	hints.ai_flags |= AI_PASSIVE;

	if (hostname != NULL)
		hints.ai_flags |= AI_CANONNAME;

	error = getaddrinfo(hostname, service, &hints, result);
	if (error) {
		pr_op_err("Could not infer a bindable address out of address '%s' and port '%s': %s",
		    (hostname != NULL) ? hostname : "any", service,
		    gai_strerror(error));
		return error;
	}

	errno = 0;
	parsed = strtoul(service, &tmp, 10);
	if (errno || *tmp != '\0')
		return 0; /* Ok, not a number */

	/*
	 * 'getaddrinfo' isn't very strict validating the service when a port
	 * number is indicated. If a port larger than the max (65535) is
	 * received, the 16 rightmost bits are utilized as the port and set at
	 * the addrinfo returned.
	 *
	 * So, a manual validation is implemented. Port is actually a uint16_t,
	 * so read what's necessary and compare using the same data type.
	 */
	port = (unsigned char)((*result)->ai_addr->sa_data[0]) << 8;
	port += (unsigned char)((*result)->ai_addr->sa_data[1]);
	if (parsed != port)
		return pr_op_err("Service port %s is out of range (max value is %d)",
		    service, USHRT_MAX);

	return 0;
}

/*
 * Creates the socket that will stay put and wait for new connections started
 * from the clients.
 */
static int
create_server_socket(char const *hostname, char const *service, int *result)
{
	struct addrinfo *addrs;
	struct addrinfo *addr;
	unsigned long port;
	int flags;
	int reuse;
	int fd; /* "file descriptor" */
	int error;

	*result = 0; /* Shuts up gcc */
	reuse = 1;

	error = init_addrinfo(hostname, service, &addrs);
	if (error)
		return error;

	if (addrs != NULL)
		pr_op_info(
		    "Attempting to bind socket to address '%s', port '%s'.",
		    (addrs->ai_canonname != NULL) ? addrs->ai_canonname : "any",
		    service);

	for (addr = addrs; addr != NULL; addr = addr->ai_next) {
		fd = socket(addr->ai_family, SOCK_STREAM, 0);
		if (fd < 0) {
			pr_op_errno(errno, "socket() failed");
			continue;
		}

		flags = fcntl(fd, F_GETFL);
		if (flags == -1) {
			pr_op_errno(errno, "fcntl() to get flags failed");
			close(fd);
			continue;
		}

		/* Non-block to allow listening on all server sockets */
		flags |= O_NONBLOCK;

		if (fcntl(fd, F_SETFL, flags) == -1) {
			pr_op_errno(errno, "fcntl() to set flags failed");
			close(fd);
			continue;
		}

		/* enable SO_REUSEADDR */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
		    sizeof(int)) < 0) {
			pr_op_errno(errno, "setsockopt(SO_REUSEADDR) failed");
			close(fd);
			continue;
		}

		/* enable SO_REUSEPORT */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse,
		    sizeof(int)) < 0) {
			pr_op_errno(errno, "setsockopt(SO_REUSEPORT) failed");
			close(fd);
			continue;
		}

		if (bind(fd, addr->ai_addr, addr->ai_addrlen) < 0) {
			pr_op_errno(errno, "bind() failed");
			close(fd);
			continue;
		}

		error = getsockname(fd, addr->ai_addr, &addr->ai_addrlen);
		if (error) {
			close(fd);
			freeaddrinfo(addrs);
			return pr_op_errno(errno, "getsockname() failed");
		}

		port = (unsigned char)(addr->ai_addr->sa_data[0]) << 8;
		port += (unsigned char)(addr->ai_addr->sa_data[1]);
		pr_op_info("Success; bound to address '%s', port '%ld'.",
		    (addr->ai_canonname != NULL) ? addr->ai_canonname : "any",
		    port);
		freeaddrinfo(addrs);
		*result = fd;
		return 0; /* Happy path */
	}

	freeaddrinfo(addrs);
	return pr_op_err("None of the addrinfo candidates could be bound.");
}

static int
fd_node_create(struct fd_node **result)
{
	struct fd_node *node;

	node = malloc(sizeof(struct fd_node));
	if (node == NULL)
		return pr_enomem();

	node->id = -1;

	*result = node;
	return 0;
}

static int
server_fd_add(struct server_fds *fds, char const *address, char const *service)
{
	struct fd_node *node;
	int error;

	node = NULL;
	error = fd_node_create(&node);
	if (error)
		return error;

	error = create_server_socket(address, service, &node->id);
	if (error) {
		free(node);
		return error;
	}

	SLIST_INSERT_HEAD(fds, node, next);
	pr_op_debug("Created server socket with FD %d.", node->id);
	return 0;
}

static void
server_fds_destroy(struct server_fds *fds)
{
	struct fd_node *fd;

	while (!SLIST_EMPTY(fds)) {
		fd = fds->slh_first;
		SLIST_REMOVE_HEAD(fds, next);
		close(fd->id);
		free(fd);
	}
	free(fds);
}

static int
parse_address(char const *full_address, char const *default_service,
    char **address, char **service)
{
	char *ptr;
	char *tmp_addr;
	char *tmp_serv;
	size_t tmp_addr_len;

	ptr = strrchr(full_address, '#');
	if (ptr == NULL) {
		tmp_addr = strdup(full_address);
		if (tmp_addr == NULL)
			return pr_enomem();

		tmp_serv = strdup(default_service);
		if (tmp_serv == NULL) {
			free(tmp_addr);
			return pr_enomem();
		}
		*address = tmp_addr;
		*service = tmp_serv;
		return 0;
	}

	if (*(ptr + 1) == '\0')
		return pr_op_err("Invalid server address '%s', can't end with '#'",
		    full_address);

	tmp_addr_len = strlen(full_address) - strlen(ptr);
	tmp_addr = malloc(tmp_addr_len + 1);
	if (tmp_addr == NULL)
		return pr_enomem();

	memcpy(tmp_addr, full_address, tmp_addr_len);
	tmp_addr[tmp_addr_len] = '\0';

	tmp_serv = strdup(ptr + 1);
	if (tmp_serv == NULL) {
		free(tmp_addr);
		return pr_enomem();
	}

	*address = tmp_addr;
	*service = tmp_serv;
	return 0;
}

static int
create_server_sockets(struct server_fds *fds)
{
	struct string_array const *addresses;
	char const *default_service;
	char *address;
	char *service;
	unsigned int i;
	int error;

	default_service = config_get_server_port();
	addresses = config_get_server_address();
	if (addresses->length == 0)
		return server_fd_add(fds, NULL, default_service);

	for (i = 0; i < addresses->length; i++) {
		address = NULL;
		service = NULL;
		error = parse_address(addresses->array[i], default_service,
		    &address, &service);
		if (error)
			return error;

		error = server_fd_add(fds, address, service);
		/* Always release them */
		free(address);
		free(service);
		if (error)
			return error;
	}

	return 0;
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

#if __linux__
	/*
	 * man 2 accept (on Linux):
	 * Linux  accept() (...) passes already-pending network errors on the
	 * new socket as an error code from accept(). This behavior differs from
	 * other BSD socket implementations. For reliable operation the
	 * application should detect the network errors defined for the protocol
	 * after accept() and treat them like EAGAIN by retrying. In the case of
	 * TCP/IP, these are (...)
	 */
	if (err == ENETDOWN || err == EPROTO || err == ENOPROTOOPT
	    || err == EHOSTDOWN || err == ENONET || err == EHOSTUNREACH
	    || err == EOPNOTSUPP || err == ENETUNREACH)
		goto retry;
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wlogical-op"
	if (err == EAGAIN || err == EWOULDBLOCK)
		goto retry;
#pragma GCC diagnostic pop

	pr_op_info("Client connection attempt not accepted: %s. Quitting...",
	    strerror(err));
	return VERDICT_EXIT;

retry:
	pr_op_info("Client connection attempt not accepted: %s. Retrying...",
	    strerror(err));
	return VERDICT_RETRY;
}

static void
clean_request(struct rtr_request *request, const struct pdu_metadata *meta)
{
	free(request->bytes);
	meta->destructor(request->pdu);
}

static int
print_close_failure(int error, struct sockaddr_storage *sockaddr)
{
	return pr_op_errno(error, "close() failed on socket of client %s",
	    sockaddr2str(sockaddr));
}

static int
end_client(struct client *client, void *arg)
{
	char const *action = arg;
	bool rejected;

	/* When we (server) are closing the connection */
	rejected = (strcmp(action, CL_REJECTED) == 0);
	if (arg != NULL && (strcmp(arg, CL_TERMINATED) == 0 || rejected))
		shutdown(client->fd, SHUT_RDWR);

	if (close(client->fd) != 0)
		return print_close_failure(errno, &client->addr);

	if (rejected) {
		pr_op_warn("Client %s [ID %d]: %s", action, client->fd,
		    sockaddr2str(&client->addr));
		pr_op_warn("Use a greater value at 'thread-pool.server.max' if you wish to accept more than %u clients.",
		    config_get_thread_pool_server_max());
		return 0;
	}

	pr_op_info("Client %s [ID %d]: %s", action, client->fd,
	    sockaddr2str(&client->addr));
	return 0;
}

static void
reject_client(int fd, struct sockaddr_storage *addr)
{
	struct client client;

	client.fd = fd;
	client.addr = *addr;

	/* Try to be polite notifying there was an error */
	err_pdu_send_internal_error(fd, RTR_V0);
	end_client(&client, CL_REJECTED);
}

/*
 * The client socket threads' entry routine.
 * @arg must be released.
 */
static void *
client_thread_cb(void *arg)
{
	struct pdu_metadata const *meta;
	struct rtr_request request;
	struct thread_param param;
	int error;

	memcpy(&param, arg, sizeof(param));
	free(arg);

	error = clients_add(param.fd, param.addr);
	if (error) {
		close(param.fd);
		return NULL;
	}

	while (true) { /* For each PDU... */
		error = pdu_load(param.fd, &param.addr, &request, &meta);
		if (error)
			break;

		error = meta->handle(param.fd, &request);
		clean_request(&request, meta);
		if (error)
			break;
	}

	clients_forget(param.fd, end_client, CL_CLOSED);

	return NULL;
}

static void
init_fdset(struct server_fds *fds, fd_set *fdset)
{
	struct fd_node *node;

	FD_ZERO(fdset);
	SLIST_FOREACH(node, fds, next)
		FD_SET(node->id, fdset);
}

/*
 * Waits for client connections and spawns threads to handle them.
 */
static void *
handle_client_connections(void *arg)
{
	struct rtr_task_param *rtr_param = arg;
	struct server_fds *fds;
	struct thread_pool *pool;
	struct sockaddr_storage client_addr;
	struct thread_param *param;
	struct timeval select_time;
	socklen_t sizeof_client_addr;
	fd_set readfds;
	int last_server_fd;
	int client_fd;
	int fd;
	int error;

	/* Get the argument pointers, and release arg at once */
	fds = rtr_param->fds;
	pool = rtr_param->pool;
	free(rtr_param);

	last_server_fd = SLIST_FIRST(fds)->id;

	sizeof_client_addr = sizeof(client_addr);

	/* I'm alive! */
	server_stop = false;

	pr_op_debug("Waiting for client connections at server...");
	do {
		/* Look for connections every .2 seconds*/
		select_time.tv_sec = 0;
		select_time.tv_usec = 200000;

		/* Am I still alive? */
		if (server_stop)
			break;

		init_fdset(fds, &readfds);

		if (select(last_server_fd + 1, &readfds, NULL, NULL,
		    &select_time) == -1) {
			pr_op_errno(errno, "Monitoring server sockets");
			continue;
		}

		for (fd = 0; fd < (last_server_fd + 1); fd++) {
			if (!FD_ISSET (fd, &readfds))
				continue;

			/* Accept the connection */
			client_fd = accept(fd, (struct sockaddr *) &client_addr,
			    &sizeof_client_addr);
			switch (handle_accept_result(client_fd, errno)) {
			case VERDICT_SUCCESS:
				break;
			case VERDICT_RETRY:
				continue;
			case VERDICT_EXIT:
				return NULL;
			}

			/*
			 * It's very likely that the clients won't release their
			 * sessions once established; so, don't let any new
			 * client at the thread pool queue since it's probable
			 * that it'll remain there forever.
			 */
			if (!thread_pool_avail_threads(pool)) {
				reject_client(client_fd, &client_addr);
				continue;
			}

			pr_op_info("Client %s [ID %d]: %s", CL_ACCEPTED,
			    client_fd, sockaddr2str(&client_addr));

			/*
			 * Note: My gut says that errors from now on (even the
			 * unknown ones) should be treated as temporary; maybe
			 * the next accept() will work.
			 * So don't interrupt the thread when this happens.
			 */

			param = malloc(sizeof(struct thread_param));
			if (param == NULL) {
				/* No error PDU on memory allocation. */
				pr_enomem();
				close(client_fd);
				continue;
			}
			param->fd = client_fd;
			param->addr = client_addr;

			error = thread_pool_push(pool, client_thread_cb,
			    param);
			if (error) {
				pr_op_err("Couldn't push a thread to attend incoming RTR client");
				/* Error with min RTR version */
				err_pdu_send_internal_error(client_fd, RTR_V0);
				close(client_fd);
				free(param);
			}
		}
	} while (true);

	return NULL; /* Unreachable. */
}

static int
__handle_client_connections(struct server_fds *fds, struct thread_pool *pool)
{
	struct rtr_task_param *param;
	struct fd_node *node;
	struct sigaction ign;
	int error;

	/* Ignore SIGPIPES, they're handled apart */
	ign.sa_handler = SIG_IGN;
	ign.sa_flags = 0;
	sigemptyset(&ign.sa_mask);
	sigaction(SIGPIPE, &ign, NULL);

	SLIST_FOREACH(node, fds, next) {
		error = listen(node->id, config_get_server_queue());
		if (error)
			return pr_op_errno(errno,
			    "Couldn't listen on server socket.");
	}

	param = malloc(sizeof(struct rtr_task_param));
	if (param == NULL)
		return pr_enomem();

	param->fds = fds;
	param->pool = pool;

	/* handle_client_connections() must release param */
	error = internal_pool_push(handle_client_connections, param);
	if (error) {
		free(param);
		return error;
	}

	return 0;
}

/*
 * Starts the server, using the current thread to listen for RTR client
 * requests. If configuration parameter 'mode' is STANDALONE, then the
 * server runs "one time" (a.k.a. run the validation just once), it doesn't
 * waits for clients requests.
 *
 * When listening for client requests, this function blocks.
 */
int
rtr_listen(void)
{
	struct server_fds *fds; /* "file descriptors" */
	struct thread_pool *pool;
	int error;

	server_stop = true;

	error = clients_db_init();
	if (error)
		return error;

	if (config_get_mode() == STANDALONE) {
		error = validation_run_first();
		goto revert_clients_db; /* Error 0 it's ok */
	}

	fds = malloc(sizeof(struct server_fds));
	if (fds == NULL) {
		error = pr_enomem();
		goto revert_clients_db;
	}

	SLIST_INIT(fds);
	error = create_server_sockets(fds);
	if (error)
		goto revert_server_fds;

	pool = NULL;
	error = thread_pool_create(config_get_thread_pool_server_max(), &pool);
	if (error)
		goto revert_server_fds;

	/* Do the first run */
	error = validation_run_first();
	if (error)
		goto revert_thread_pool;

	/* Wait for connections at another thread */
	error = __handle_client_connections(fds, pool);
	if (error)
		goto revert_thread_pool;

	/* Keep running the validations on the main thread */
	error = validation_run_cycle();

	/* Terminate all clients */
	clients_terminate_all(end_client, CL_TERMINATED);

	/* Stop the server (it lives on a detached thread) */
	server_stop = true;

revert_thread_pool:
	thread_pool_destroy(pool);
revert_server_fds:
	server_fds_destroy(fds);
revert_clients_db:
	clients_db_destroy();
	return error;
}
