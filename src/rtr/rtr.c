#include "rtr/rtr.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "config.h"
#include "data_structure/array_list.h"
#include "log.h"
#include "rtr/pdu_handler.h"
#include "rtr/pdu_sender.h"
#include "stats.h"
#include "types/address.h"

struct rtr_server {
	int fd;
	/* Printable address to which the server was bound. */
	char *addr;
};

struct server_init_ctx {
	/* Server binding address string, exactly as received from the user. */
	char const *input_addr;
#ifdef __linux__
	/* Have we already attempted to bind a wildcard address? */
	bool wildcard_found;
#endif
};

static pthread_t control_thread;
static pthread_t *server_threads;

STATIC_ARRAY_LIST(server_arraylist, struct rtr_server)
STATIC_ARRAY_LIST(client_arraylist, struct pdu_stream *)

static struct server_arraylist servers;
static struct client_arraylist clients;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t parent2worker;

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
_pdustream_destroy(struct pdu_stream **stream)
{
	if (stream)
		pdustream_destroy(*stream);
}

static void
destroy_db(void)
{
	server_arraylist_cleanup(&servers, cleanup_server);
	client_arraylist_cleanup(&clients, _pdustream_destroy);
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
	struct addrinfo hints;
	int error;

	memset(&hints, 0 , sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
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

	return 0;
}

#ifdef __linux__

static bool
is_wildcard(struct sockaddr *sa)
{
	static const struct in6_addr wildcard6 = { 0 };
	struct in_addr *addr4;
	struct in6_addr *addr6;

	switch (sa->sa_family) {
	case AF_INET:
		addr4 = &((struct sockaddr_in *) sa)->sin_addr;
		return addr4->s_addr == 0;
	case AF_INET6:
		addr6 = &((struct sockaddr_in6 *) sa)->sin6_addr;
		return addr6_equals(&wildcard6, addr6);
	}

	return false;
}

#endif

static char *
get_best_printable(struct addrinfo *addr, char const *input_addr)
{
	char str[INET6_ADDRSTRLEN];

	if (sockaddr2str((struct sockaddr_storage *) addr->ai_addr, str))
		return pstrdup(str);

	if (input_addr != NULL)
		return pstrdup(input_addr);

	/* Failure is fine; this is just a nice-to-have. */
	return NULL;
}

/*
 * We want to listen to all sockets in one thread,
 * so don't block.
 *
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
create_server_socket(struct server_init_ctx *ctx, char const *hostname, char const *port)
{
	struct addrinfo *ais, *ai;
	struct rtr_server server;
	char const *errmsg;
	static const int yes = 1;
	int err;

	err = init_addrinfo(hostname, port, &ais);
	if (err)
		return err;

	for (ai = ais; ai != NULL; ai = ai->ai_next) {
#ifdef __linux__
		if (is_wildcard(ai->ai_addr)) {
			if (ctx->wildcard_found)
				pr_op_warn("You have more than one wildcard address in server.address, and you're on Linux.\n"
				    "On Linux, :: implies 0.0.0.0 by default, and you can't bind to 0.0.0.0 twice.\n"
				    "The socket bind is probably going to fail.\n"
				    "If you meant to bind to any address on both IPv4 and IPv6, you only need '::'.");
			ctx->wildcard_found = true;
		}
#endif

		server.fd = -1;
		server.addr = get_best_printable(ai, ctx->input_addr);
		pr_op_info("[%s]:%s: Setting up socket...", server.addr, port);

		server.fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (server.fd < 0) {
			err = errno;
			errmsg = "Unable to create socket";
			goto fail;
		}

		if ((err = set_nonblock(server.fd)) != 0) {
			errmsg = "Unable to disable blocking on the socket";
			goto fail;
		}

		if (setsockopt(server.fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
			err = errno;
			errmsg = "Unable to enable SO_REUSEADDR on the socket";
			goto fail;
		}

		if (bind(server.fd, ai->ai_addr, ai->ai_addrlen) < 0) {
			err = errno;
			errmsg = "Unable to bind the socket";
			goto fail;
		}

		if (listen(server.fd, config_get_server_queue()) < 0) {
			err = errno;
			errmsg = "Unable to start listening on socket";
			goto fail;
		}

		pr_op_info("[%s]:%s: Success.", server.addr, port);
		server_arraylist_add(&servers, &server);
	}

	freeaddrinfo(ais);
	return 0;

fail:
	pr_op_err("[%s]:%s: %s: %s", server.addr, port, errmsg, strerror(err));
	if (server.fd != -1)
		close(server.fd);
	free(server.addr);
	freeaddrinfo(ais);
	return err;
}

static int
init_server_fd(struct server_init_ctx *ctx)
{
	char *address;
	char *service;
	int error;

	address = NULL;
	service = NULL;

	error = parse_address(ctx->input_addr, &address, &service);
	if (error)
		return error;

	error = create_server_socket(ctx, address, service);

	free(address);
	free(service);

	return error;
}

static int
init_server_fds(void)
{
	struct server_init_ctx ctx = { 0 };
	struct string_array const *conf_addrs;
	unsigned int i;
	int error;

	conf_addrs = config_get_server_address();

	if (conf_addrs->length == 0)
		return init_server_fd(&ctx);

	for (i = 0; i < conf_addrs->length; i++) {
		ctx.input_addr = conf_addrs->array[i];
		error = init_server_fd(&ctx);
		if (error)
			return error; /* Cleanup happens outside */
	}

	return 0;
}

static struct pdu_stream *
claim_client(void)
{
	struct pdu_stream **_client, *client;

	ARRAYLIST_FOREACH(&clients, _client) {
		client = *_client;
		if (!TAILQ_EMPTY(&client->requests) && !client->claimed) {
			client->claimed = true;
			return client;
		}
	}

	return NULL;
}

static struct rtr_request *
next_request(struct pdu_stream *client)
{
	struct rtr_request *req;

	req = TAILQ_FIRST(&client->requests);
	if (req) {
		TAILQ_REMOVE(&client->requests, req, lh);
		client->reqcount--;
	}

	return req;
}

static void
handle_request(struct rtr_request *req)
{
	switch (req->pdu.type) {
	case PDU_TYPE_SERIAL_QUERY:
		handle_serial_query_pdu(req);
		break;
	case PDU_TYPE_RESET_QUERY:
		handle_reset_query_pdu(req);
		break;
	default:
		/* Should have been catched during constructor */
		pr_crit("Unexpected PDU type: %u",
		    req->pdu.type);
	}

	rtreq_destroy(req);
}

static void *
handle_clients(void *arg)
{
	struct pdu_stream *client;
	struct rtr_request *req;

	mutex_lock(&lock);

	while (!fort_end) {
		client = claim_client();
		if (!client) {
			panic_on_fail(pthread_cond_wait(&parent2worker, &lock),
			    "pthread_cond_wait");
			continue;
		}

		while ((req = next_request(client)) != NULL) {
			mutex_unlock(&lock);
			handle_request(req);
			mutex_lock(&lock);
		}

		client->claimed = false;
	}

	mutex_unlock(&lock);
	return NULL;
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
	size_t src;
	size_t dst;

	for (src = 0, dst = 0; src < clients.len; src++) {
		if (clients.array[src] != NULL) {
			clients.array[dst] = clients.array[src];
			dst++;
		}
	}

	clients.len = dst;
}

static void
apply_pollfds(struct pollfd *pollfds, size_t nclients)
{
	struct rtr_server *server;
	struct pdu_stream *client;
	size_t i;

	for (i = 0; i < servers.len; i++) {
		server = &servers.array[i];

		/* PR_DEBUG_MSG("pfd:%d server:%d", pfd->fd, server->fd); */

		if ((pollfds[i].fd == -1) && (server->fd != -1)) {
			close(server->fd);
			server->fd = -1;
		}
	}

	for (i = 0; i < nclients; i++) {
		client = clients.array[i];

		/* PR_DEBUG_MSG("pfd:%d client:%d", pfd->fd, client->fd); */

		if (client->eos && TAILQ_EMPTY(&client->requests)) {
			pdustream_destroy(client);
			clients.array[i] = NULL;
		}
	}

	delete_dead_clients();
}

static void
disable_read(struct pdu_stream *stream)
{
	pr_op_debug("Shutting down input stream of client %s.", stream->addr);
	if (shutdown(stream->fd, SHUT_RD) < 0)
		pr_op_warn("Can't shut down read end of client socket: %s",
		    strerror(errno));
	stream->eos = true;
}

static enum poll_verdict
fddb_poll(void)
{
	struct pollfd *pollfds; /* array */
	struct pollfd *fd;
	struct pdu_stream *client;
	size_t nclients;
	size_t i;
	bool wakeup;
	int error;

	pollfds = pcalloc(servers.len + clients.len, sizeof(struct pollfd));

	ARRAYLIST_FOREACH_IDX(&servers, i)
		init_pollfd(&pollfds[i], servers.array[i].fd);
	ARRAYLIST_FOREACH_IDX(&clients, i)
		init_pollfd(
		    &pollfds[servers.len + i],
		    clients.array[i]->eos ? -1 : clients.array[i]->fd
		);

	error = poll(pollfds, servers.len + clients.len, 1000);

	if (fort_end)
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
			print_poll_failure(fd, "Server", servers.array[i].addr);
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
	wakeup = false;
	mutex_lock(&lock);

	for (i = 0; i < nclients; i++) {
		/* This fd is a client handler socket. */
		fd = &pollfds[servers.len + i];
		client = clients.array[i];

		/* PR_DEBUG_MSG("Client %u: fd:%d revents:%x", i, fd->fd,
		    fd->revents); */

		if (fd->fd == -1)
			continue;

		if (fd->revents & (POLLHUP | POLLERR | POLLNVAL)) {
			print_poll_failure(fd, "Client", client->addr);
			disable_read(client);

		} else if (fd->revents & POLLIN) {
			if (!pdustream_parse(client, &wakeup))
				disable_read(client);
		}
	}

	apply_pollfds(pollfds, nclients);
	nclients = clients.len;

	if (wakeup)
		panic_on_fail(pthread_cond_broadcast(&parent2worker),
		    "pthread_cond_broadcast");

	mutex_unlock(&lock);

	stats_gauge_set(stat_rtr_connections, nclients);
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
control_cb(void *arg)
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

static void
end_server_threads(size_t count)
{
	array_index i;
	int error;

	fort_end = true;
	pthread_cond_broadcast(&parent2worker);
	for (i = 0; i < count; i++) {
		error = pthread_join(server_threads[i], NULL);
		if (error)
			pr_op_warn("pthread_join: %s", strerror(error));
		pr_op_debug("Ended RTR server thread #%zu.", i + 1);
	}
}

int
rtr_start(void)
{
	array_index i;
	int error;

	rtridx_expire();

	server_arraylist_init(&servers);
	client_arraylist_init(&clients);

	error = init_server_fds();
	if (error)
		goto revert_fds;

	error = pthread_cond_init(&parent2worker, NULL);
	if (error) {
		pr_op_err_st("pthread_cond_init(p2w) returned error %d: %s",
		    error, strerror(error));
		goto revert_fds;
	}

	server_threads = pcalloc(config_get_thread_pool_server_max(),
	    sizeof(pthread_t));
	for (i = 0; i < config_get_thread_pool_server_max(); i++) {
		error = pthread_create(&server_threads[i], NULL,
		    handle_clients, NULL);
		if (error) {
			pr_op_err_st("pthread_create() returned error %d: %s",
			    error, strerror(error));
			goto revert_threads;
		}

		pr_op_debug("Spawned RTR server thread #%zu.", i + 1);
	}

	error = pthread_create(&control_thread, NULL, control_cb, NULL);
	if (error)
		goto revert_threads;

	return 0;

revert_threads:
	end_server_threads(i);
revert_fds:
	destroy_db();
	return error;
}

void rtr_stop(void)
{
	int error;

	end_server_threads(config_get_thread_pool_server_max());

	error = pthread_join(control_thread, NULL);
	if (error) {
		pr_op_err("pthread_join() returned error %d: %s", error,
		    strerror(error));
	}

	free(server_threads);
	pthread_cond_destroy(&parent2worker);
	destroy_db();
}

void
rtr_notify(struct rtr_metadata *rtr)
{
	struct pdu_stream **_client, *client;

	mutex_lock(&lock);

	ARRAYLIST_FOREACH(&clients, _client) {
		client = *_client;
		if (client->fd != -1)
			send_serial_notify_pdu(
			    client->fd,
			    client->rtr_version,
			    rtr
			);
	}

	mutex_unlock(&lock);
}
