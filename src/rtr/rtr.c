#include "rtr.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <log.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "config.h"
#include "types/address.h"
#include "data_structure/array_list.h"
#include "rtr/pdu.h"
#include "thread/thread_pool.h"

static pthread_t server_thread;
static volatile bool stop_server_thread;

STATIC_ARRAY_LIST(server_arraylist, struct rtr_server)
STATIC_ARRAY_LIST(client_arraylist, struct rtr_client)

static struct server_arraylist servers;
static struct client_arraylist clients;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct thread_pool *request_handlers;

#define REQUEST_BUFFER_LEN 1024

struct client_request {
	struct rtr_client *client;
	unsigned char buffer[REQUEST_BUFFER_LEN];
	size_t nread;
};

enum poll_verdict {
	PV_CONTINUE,
	PV_RETRY, /* Pause for a while, then continue */
	PV_STOP,
};

static void
panic_on_fail(int error, char const *function_name)
{
	if (error)
		pr_crit("%s() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    function_name, error);
}

static void
lock_mutex(void)
{
	panic_on_fail(pthread_mutex_lock(&lock), "pthread_mutex_lock");
}

static void
unlock_mutex(void)
{
	panic_on_fail(pthread_mutex_unlock(&lock), "pthread_mutex_unlock");
}

static void
cleanup_server(struct rtr_server *server)
{
	if (server->fd != -1)
		close(server->fd);
	free(server->addr);
}

static void
cleanup_client(struct rtr_client *client)
{
	if (client->fd != -1) {
		shutdown(client->fd, SHUT_RDWR);
		close(client->fd);
	}
}

static void
destroy_db(void)
{
	server_arraylist_cleanup(&servers, cleanup_server);
	client_arraylist_cleanup(&clients, cleanup_client);
}

/*
 * Extracts from @full_address ("IP#[port]") the address and port, and returns
 * them in @address and @service, respectively.
 *
 * The default port is config_get_server_port().
 */
static int
parse_address(char const *full_address, char **address, char **service)
{
	char *ptr;
	char *tmp_addr;
	char *tmp_serv;
	size_t tmp_addr_len;

	if (full_address == NULL) {
		tmp_addr = NULL;
		tmp_serv = strdup(config_get_server_port());
		if (tmp_serv == NULL)
			return pr_enomem();
		goto done;
	}

	ptr = strrchr(full_address, '#');
	if (ptr == NULL) {
		tmp_addr = strdup(full_address);
		if (tmp_addr == NULL)
			return pr_enomem();

		tmp_serv = strdup(config_get_server_port());
		if (tmp_serv == NULL) {
			free(tmp_addr);
			return pr_enomem();
		}

		goto done;
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

	/* Fall through */
done:
	*address = tmp_addr;
	*service = tmp_serv;
	return 0;
}

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
 * By the way: man 2 poll says
 *
 * > The operation of poll() and ppoll() is not affected by the O_NONBLOCK flag.
 *
 * Which appears to be untrue. If I remove this function, both client and server
 * hang forever, apparently after the TCP handshake.
 */
static int
set_nonblock(int fd)
{
	int flags;
	int error;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		error = errno;
		pr_op_err("fcntl() to get flags failed: %s", strerror(error));
		return error;
	}

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1) {
		error = errno;
		pr_op_err("fcntl() to set flags failed: %s", strerror(error));
		return error;
	}

	return 0;
}

/*
 * Creates the socket that will stay put and wait for new connections started
 * from the clients.
 */
static int
create_server_socket(char const *input_addr, char const *hostname,
    char const *service)
{
	struct addrinfo *addrs;
	struct addrinfo *addr;
	unsigned long port;
	int reuse;
	int fd;
	struct rtr_server server;
	int error;

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
			pr_op_err("socket() failed: %s", strerror(errno));
			continue;
		}

		/*
		 * We want to listen to all sockets in one thread,
		 * so don't block.
		 */
		if (set_nonblock(fd) != 0) {
			close(fd);
			continue;
		}

		/* enable SO_REUSEADDR */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
		    sizeof(int)) < 0) {
			pr_op_err("setsockopt(SO_REUSEADDR) failed: %s",
			    strerror(errno));
			close(fd);
			continue;
		}

		/* enable SO_REUSEPORT */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse,
		    sizeof(int)) < 0) {
			pr_op_err("setsockopt(SO_REUSEPORT) failed: %s",
			    strerror(errno));
			close(fd);
			continue;
		}

		if (bind(fd, addr->ai_addr, addr->ai_addrlen) < 0) {
			pr_op_err("bind() failed: %s", strerror(errno));
			close(fd);
			continue;
		}

		if (getsockname(fd, addr->ai_addr, &addr->ai_addrlen) != 0) {
			error = errno;
			close(fd);
			freeaddrinfo(addrs);
			pr_op_err("getsockname() failed: %s", strerror(error));
			return error;
		}

		port = (unsigned char)(addr->ai_addr->sa_data[0]) << 8;
		port += (unsigned char)(addr->ai_addr->sa_data[1]);
		pr_op_info("Success; bound to address '%s', port '%ld'.",
		    (addr->ai_canonname != NULL) ? addr->ai_canonname : "any",
		    port);
		freeaddrinfo(addrs);

		if (listen(fd, config_get_server_queue()) != 0) {
			error = errno;
			close(fd);
			pr_op_err("listen() failure: %s", strerror(error));
			return error;
		}

		server.fd = fd;
		/* Ignore failure; this is just a nice-to-have. */
		server.addr = (input_addr != NULL) ? strdup(input_addr) : NULL;
		error = server_arraylist_add(&servers, &server);
		if (error) {
			close(fd);
			return error;
		}

		return 0; /* Happy path */
	}

	freeaddrinfo(addrs);
	return pr_op_err("None of the addrinfo candidates could be bound.");
}

static int
init_server_fd(char const *input_addr)
{
	char *address;
	char *service;
	int error;

	address = NULL;
	service = NULL;

	error = parse_address(input_addr, &address, &service);
	if (error)
		return error;

	error = create_server_socket(input_addr, address, service);

	free(address);
	free(service);

	return error;
}

static int
init_server_fds(void)
{
	struct string_array const *conf_addrs;
	unsigned int i;
	int error;

	conf_addrs = config_get_server_address();

	if (conf_addrs->length == 0)
		return init_server_fd(NULL);

	for (i = 0; i < conf_addrs->length; i++) {
		error = init_server_fd(conf_addrs->array[i]);
		if (error)
			return error; /* Cleanup happens outside */
	}

	return 0;
}

static void
handle_client_request(void *arg)
{
	struct client_request *crequest = arg;
	struct pdu_reader reader;
	struct rtr_request rrequest;
	struct pdu_metadata const *meta;

	pdu_reader_init(&reader, crequest->buffer, crequest->nread);

	while (pdu_load(&reader, crequest->client, &rrequest, &meta) == 0) {
		meta->handle(crequest->client->fd, &rrequest);
		meta->destructor(rrequest.pdu);
	}

	free(crequest);
}

static void
init_pollfd(struct pollfd *pfd, int fd)
{
	pfd->fd = fd;
	pfd->events = POLLIN;
	pfd->revents = 0;
}

enum accept_verdict {
	AV_SUCCESS,
	AV_CLIENT_ERROR,
	AV_SERVER_ERROR,
};

/*
 * Converts an error code to a verdict.
 * The error code is assumed to have been spewed by the `accept()` function.
 */
static enum accept_verdict
handle_accept_result(int client_fd, int err)
{
	if (client_fd >= 0)
		return AV_SUCCESS;

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

	if (err == EAGAIN)
		goto retry;
	if (err == EWOULDBLOCK)
		goto retry;

	pr_op_info("Client connection attempt not accepted: %s. Quitting...",
	    strerror(err));
	return AV_SERVER_ERROR;

retry:
	pr_op_info("Client connection attempt not accepted: %s. Retrying...",
	    strerror(err));
	return AV_CLIENT_ERROR;
}

static enum accept_verdict
accept_new_client(struct pollfd const *server_fd)
{
	struct sockaddr_storage client_addr;
	socklen_t sizeof_client_addr;
	struct rtr_client client;
	enum accept_verdict result;

	sizeof_client_addr = sizeof(client_addr);

	/* Accept the connection */
	client.fd = accept(server_fd->fd, (struct sockaddr *) &client_addr,
	    &sizeof_client_addr);

	result = handle_accept_result(client.fd, errno);
	if (result != AV_SUCCESS)
		return result;

	if (set_nonblock(client.fd) != 0) {
		close(client.fd);
		return AV_CLIENT_ERROR;
	}

	client.rtr_version = -1;
	sockaddr2str(&client_addr, client.addr);
	if (client_arraylist_add(&clients, &client) != 0) {
		close(client.fd);
		return AV_CLIENT_ERROR;
	}

	pr_op_info("Client accepted [FD: %d]: %s", client.fd, client.addr);
	return AV_SUCCESS;
}

/*
 * true: success.
 * false: oh noes; close socket.
 */
static bool
read_until_block(int fd, struct client_request *request)
{
	ssize_t read_result;
	size_t offset;
	int error;

	request->nread = 0;

	for (offset = 0; offset < REQUEST_BUFFER_LEN; offset += read_result) {
		read_result = read(fd, &request->buffer[offset],
		    REQUEST_BUFFER_LEN - offset);
		if (read_result == -1) {
			error = errno;
			if (error == EAGAIN || error == EWOULDBLOCK)
				return true; /* Ok, we have the full packet. */

			pr_op_err("Client socket read interrupted: %s",
			    strerror(error));
			return false;
		}

		if (read_result == 0) {
			if (offset == 0) {
				pr_op_debug("Client closed the socket.");
				return false;
			}

			return true; /* Ok, we have the last packet. */
		}

		request->nread += read_result;
	}

	pr_op_warn("Peer's request is too big (>= %u bytes). Peer does not look like an RTR client; closing connection.",
	    REQUEST_BUFFER_LEN);
	return false;
}

static bool
__handle_client_request(struct rtr_client *client)
{
	struct client_request *request;
	int error;

	request = malloc(sizeof(struct client_request));
	if (request == NULL) {
		pr_enomem();
		return false;
	}

	request->client = client;
	if (!read_until_block(client->fd, request))
		goto cancel;

	pr_op_debug("Client sent %zu bytes.", request->nread);
	error = thread_pool_push(request_handlers, "RTR request",
	    handle_client_request, request);
	if (error)
		goto cancel;

	return true;

cancel:
	free(request);
	return false;
}

static void
print_poll_failure(struct pollfd *pfd, char const *what, char const *addr)
{
	if (pfd->revents & POLLHUP)
		pr_op_err("%s '%s' down: POLLHUP (Peer hung up)", what, addr);
	if (pfd->revents & POLLERR)
		pr_op_err("%s '%s' down: POLLERR (Generic error)", what, addr);
	if (pfd->revents & POLLNVAL)
		pr_op_err("%s '%s' down: POLLNVAL (fd not open)", what, addr);
}

static void
delete_dead_clients(void)
{
	unsigned int src;
	unsigned int dst;

	for (src = 0, dst = 0; src < clients.len; src++) {
		if (clients.array[src].fd != -1) {
			clients.array[dst] = clients.array[src];
			dst++;
		}
	}

	clients.len = dst;
}

static void
apply_pollfds(struct pollfd *pollfds, unsigned int nclients)
{
	struct pollfd *pfd;
	struct rtr_server *server;
	struct rtr_client *client;
	unsigned int i;

	for (i = 0; i < servers.len; i++) {
		pfd = &pollfds[i];
		server = &servers.array[i];

		/* PR_DEBUG_MSG("pfd:%d server:%d", pfd->fd, server->fd); */

		if ((pfd->fd == -1) && (server->fd != -1)) {
			close(server->fd);
			server->fd = -1;
			print_poll_failure(pfd, "Server", server->addr);
		}
	}

	for (i = 0; i < nclients; i++) {
		pfd = &pollfds[servers.len + i];
		client = &clients.array[i];

		/* PR_DEBUG_MSG("pfd:%d client:%d", pfd->fd, client->fd); */

		if ((pfd->fd == -1) && (client->fd != -1)) {
			close(client->fd);
			client->fd = -1;
			print_poll_failure(pfd, "Client", client->addr);
		}
	}

	delete_dead_clients();
}

static enum poll_verdict
fddb_poll(void)
{
	struct pollfd *pollfds; /* array */

	struct rtr_server *server;
	struct rtr_client *client;
	struct pollfd *fd;

	unsigned int nclients;
	unsigned int i;
	int error;

	pollfds = calloc(servers.len + clients.len, sizeof(struct pollfd));
	if (pollfds == NULL) {
		pr_enomem();
		return PV_RETRY;
	}

	ARRAYLIST_FOREACH(&servers, server, i)
		init_pollfd(&pollfds[i], server->fd);
	ARRAYLIST_FOREACH(&clients, client, i)
		init_pollfd(&pollfds[servers.len + i], client->fd);

	error = poll(pollfds, servers.len + clients.len, 1000);

	if (stop_server_thread)
		goto stop;

	if (error == 0)
		goto success;

	if (error < 0) {
		error = errno;
		switch (error) {
		case EINTR:
			pr_op_info("poll() was interrupted by some signal.");
			goto stop;
		case ENOMEM:
			pr_enomem();
			/* Fall through */
		case EAGAIN:
			goto retry;
		case EFAULT:
		case EINVAL:
			pr_crit("poll() returned %d.", error);
		}
	}

	/* The servers might change this number, so store a backup. */
	nclients = clients.len;

	/* New connections */
	for (i = 0; i < servers.len; i++) {
		/* This fd is a listening socket. */
		fd = &pollfds[i];

		/* PR_DEBUG_MSG("Server %u: fd:%d revents:%x",
		    i, fd->fd, fd->revents); */

		if (fd->fd == -1)
			continue;

		if (fd->revents & (POLLHUP | POLLERR | POLLNVAL)) {
			fd->fd = -1;

		} else if (fd->revents & POLLIN) {
			switch (accept_new_client(fd)) {
			case AV_SUCCESS:
			case AV_CLIENT_ERROR:
				break;
			case AV_SERVER_ERROR:
				fd->fd = -1;
			}
		}
	}

	/* Client requests */
	for (i = 0; i < nclients; i++) {
		/* This fd is a client handler socket. */
		fd = &pollfds[servers.len + i];

		/* PR_DEBUG_MSG("Client %u: fd:%d revents:%x", i, fd->fd,
		    fd->revents); */

		if (fd->fd == -1)
			continue;

		if (fd->revents & (POLLHUP | POLLERR | POLLNVAL)) {
			fd->fd = -1;
		} else if (fd->revents & POLLIN) {
			if (!__handle_client_request(&clients.array[i]))
				fd->fd = -1;
		}
	}

	lock_mutex();
	apply_pollfds(pollfds, nclients);
	unlock_mutex();
	/* Fall through */

success:
	free(pollfds);
	return PV_CONTINUE;
retry:
	free(pollfds);
	return PV_RETRY;
stop:
	free(pollfds);
	return PV_STOP;
}

static void *
server_cb(void *arg)
{
	do {
		switch (fddb_poll()) {
		case PV_CONTINUE:
			break;
		case PV_RETRY:
			sleep(1);
			break;
		case PV_STOP:
			return NULL;
		}
	} while (true);
}

int
rtr_start(void)
{
	int error;

	server_arraylist_init(&servers);
	client_arraylist_init(&clients);

	error = init_server_fds();
	if (error)
		goto revert_fds;

	error = thread_pool_create("Server",
	    config_get_thread_pool_server_max(),
	    &request_handlers);
	if (error)
		goto revert_fds;

	error = pthread_create(&server_thread, NULL, server_cb, NULL);
	if (error) {
		thread_pool_destroy(request_handlers);
		goto revert_fds;
	}

	return 0;

revert_fds:
	destroy_db();
	return error;
}

void rtr_stop(void)
{
	int error;

	stop_server_thread = true;
	error = pthread_join(server_thread, NULL);
	if (error) {
		pr_op_err("pthread_join() returned error %d: %s", error,
		    strerror(error));
	}

	thread_pool_destroy(request_handlers);

	destroy_db();
}

int
rtr_foreach_client(rtr_foreach_client_cb cb, void *arg)
{
	struct rtr_client *client;
	unsigned int i;
	int error = 0;

	lock_mutex();

	ARRAYLIST_FOREACH(&clients, client, i) {
		if (client->fd != -1) {
			error = cb(client, arg);
			if (error)
				break;
		}
	}

	unlock_mutex();

	return error;
}
