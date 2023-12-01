#include "rtr/rtr.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "alloc.h"
#include "config.h"
#include "types/address.h"
#include "data_structure/array_list.h"
#include "rtr/err_pdu.h"
#include "rtr/pdu.h"
#include "rtr/pdu_handler.h"
#include "rtr/pdu_sender.h"
#include "rtr/pdu_stream.h"
#include "rtr/db/vrps.h"
#include "thread/thread_pool.h"
#include "types/serial.h"

struct rtr_server {
	int fd;
	/* Printable address to which the server was bound. */
	char *addr;
};

static pthread_t server_thread;
static volatile bool stop_server_thread;

STATIC_ARRAY_LIST(server_arraylist, struct rtr_server)
STATIC_ARRAY_LIST(client_arraylist, struct pdu_stream *)

static struct server_arraylist servers;
static struct client_arraylist clients;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static struct thread_pool *request_handlers;

enum poll_verdict {
	PV_CONTINUE,
	PV_RETRY, /* Pause for a while, then continue */
	PV_STOP,
};

static void
cleanup_server(struct rtr_server *server)
{
	if (server->fd != -1)
		close(server->fd);
	free(server->addr);
}

static void
destroy_db(void)
{
	server_arraylist_cleanup(&servers, cleanup_server);
	client_arraylist_cleanup(&clients, pdustream_destroy);
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
	char const *ptr;
	char *tmp_addr;
	char *tmp_serv;
	size_t tmp_addr_len;

	if (full_address == NULL) {
		tmp_addr = NULL;
		tmp_serv = pstrdup(config_get_server_port());
		goto done;
	}

	ptr = strrchr(full_address, '#');
	if (ptr == NULL) {
		tmp_addr = pstrdup(full_address);
		tmp_serv = pstrdup(config_get_server_port());
		goto done;
	}

	if (*(ptr + 1) == '\0')
		return pr_op_err("Invalid server address '%s', can't end with '#'",
		    full_address);

	tmp_addr_len = strlen(full_address) - strlen(ptr);
	tmp_addr = pmalloc(tmp_addr_len + 1);

	memcpy(tmp_addr, full_address, tmp_addr_len);
	tmp_addr[tmp_addr_len] = '\0';

	tmp_serv = pstrdup(ptr + 1);
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
		pr_op_err_st("fcntl() to get flags failed: %s", strerror(error));
		return error;
	}

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1) {
		error = errno;
		pr_op_err_st("fcntl() to set flags failed: %s", strerror(error));
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
		server.addr = (input_addr != NULL) ? pstrdup(input_addr) : NULL;
		server_arraylist_add(&servers, &server);

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
	struct rtr_request *request = arg;

	switch (request->pdu.type) {
	case PDU_TYPE_SERIAL_QUERY:
		handle_serial_query_pdu(request);
		break;
	case PDU_TYPE_RESET_QUERY:
		handle_reset_query_pdu(request);
		break;
	default:
		/* Should have been catched during constructor */
		pr_crit("Unexpected PDU type: %u", request->pdu.type);
	}

	if (request->eos)
		/* Wake poller to close the socket */
		shutdown(request->fd, SHUT_WR);

	rtreq_destroy(request);
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
	int fd;
	char addr[INET6_ADDRSTRLEN];
	struct pdu_stream *client;
	enum accept_verdict result;

	sizeof_client_addr = sizeof(client_addr);

	fd = accept(server_fd->fd, (struct sockaddr *) &client_addr,
	    &sizeof_client_addr);

	result = handle_accept_result(fd, errno);
	if (result != AV_SUCCESS)
		return result;

	if (set_nonblock(fd) != 0) {
		close(fd);
		return AV_CLIENT_ERROR;
	}

	sockaddr2str(&client_addr, addr);
	client = pdustream_create(fd, addr);

	client_arraylist_add(&clients, &client);

	pr_op_info("Client accepted [FD: %d]: %s", fd, addr);
	return AV_SUCCESS;
}

static bool
__handle_client_request(struct pdu_stream *stream)
{
	struct rtr_request *request;

	if (!pdustream_next(stream, &request))
		return false;

	if (request == NULL)
		return true;

	thread_pool_push(request_handlers, "RTR request", handle_client_request,
	    request);
	return true;
}

static void
print_poll_failure(struct pollfd *pfd, char const *what, char const *addr)
{
	/*
	 * Note, POLLHUP and POLLER are implemented somewhat differently across
	 * the board: http://www.greenend.org.uk/rjk/tech/poll.html
	 */

	if (pfd->revents & POLLHUP) {
		/* Normal; we don't have control over the client. */
		pr_op_info("%s '%s' down: Peer hung up. (Revents 0x%02x)",
		    what, addr, pfd->revents);
	}
	if (pfd->revents & POLLERR) {
		/*
		 * The documentation of this one stinks. The UNIX spec and
		 * OpenBSD mostly unhelpfully define it as "An error has
		 * occurred," and Linux appends "read end has been closed"
		 * (which doesn't seem standard).
		 *
		 * I often get it when the client closes the socket while the
		 * handler thread is sending it data (Making it a synonym to
		 * POLLHUP in this case), so we can't make too much of a fuss
		 * when it shows up.
		 *
		 * Warning it is.
		 */
		pr_op_warn("%s '%s' down: Generic error. (Revents 0x%02x)",
		    what, addr, pfd->revents);
	}
	if (pfd->revents & POLLNVAL) {
		/*
		 * Definitely suggests a programming error.
		 * We're the main polling thread, so nobody else should be
		 * closing sockets on us.
		 */
		pr_op_err("%s '%s' down: File Descriptor closed. (Revents 0x%02x)",
		    what, addr, pfd->revents);
	}
}

static void
delete_dead_clients(void)
{
	unsigned int src;
	unsigned int dst;

	for (src = 0, dst = 0; src < clients.len; src++) {
		if (clients.array[src] != NULL) {
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
	struct pdu_stream *client;
	unsigned int i;

	for (i = 0; i < servers.len; i++) {
		pfd = &pollfds[i];
		server = &servers.array[i];

		/* PR_DEBUG_MSG("pfd:%d server:%d", pfd->fd, server->fd); */

		if ((pfd->fd == -1) && (server->fd != -1)) {
			print_poll_failure(pfd, "Server", server->addr);
			close(server->fd);
			server->fd = -1;
		}
	}

	for (i = 0; i < nclients; i++) {
		pfd = &pollfds[servers.len + i];
		client = clients.array[i];

		/* PR_DEBUG_MSG("pfd:%d client:%d", pfd->fd, client->fd); */

		if ((pfd->fd == -1) && (pdustream_fd(client) != -1)) {
			print_poll_failure(pfd, "Client", pdustream_addr(client));
			pdustream_destroy(&client);
			clients.array[i] = NULL;
		}
	}

	delete_dead_clients();
}

static enum poll_verdict
fddb_poll(void)
{
	struct pollfd *pollfds; /* array */
	struct pollfd *fd;
	unsigned int nclients;
	unsigned int i;
	int error;

	pollfds = pcalloc(servers.len + clients.len, sizeof(struct pollfd));

	ARRAYLIST_FOREACH_IDX(&servers, i)
		init_pollfd(&pollfds[i], servers.array[i].fd);
	ARRAYLIST_FOREACH_IDX(&clients, i)
		init_pollfd(&pollfds[servers.len + i], pdustream_fd(clients.array[i]));

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
			enomem_panic();
		case EAGAIN:
			goto retry;
		case EFAULT:
		case EINVAL:
			pr_crit("poll() returned %d.", error);
		}
	}

	/* accept_new_client() might change this number, so store a backup. */
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

		if (fd->revents & (POLLHUP | POLLERR | POLLNVAL)) {
			fd->fd = -1;
		} else if (fd->revents & POLLIN) {
			if (!__handle_client_request(clients.array[i]))
				fd->fd = -1;
		}
	}

	mutex_lock(&lock);
	apply_pollfds(pollfds, nclients);
	mutex_unlock(&lock);
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

void
rtr_notify(void)
{
	serial_t serial;
	struct pdu_stream **client;
	int fd;
	int error;

	error = get_last_serial_number(&serial);
	if (error) {
		pr_op_info("Can't notify RTR clients: %d (%s)", error,
		    strerror(abs(error)));
		return;
	}

	mutex_lock(&lock);

	ARRAYLIST_FOREACH(&clients, client) {
		fd = pdustream_fd(*client);
		if (fd != -1)
			send_serial_notify_pdu(fd, pdustream_version(*client),
			    serial);
	}

	mutex_unlock(&lock);
}
