
// Socket server adapted from
// http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/server.c

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>

#include "zcoap-server.h"
#include "private.h"
#include "public.h"

#define NELM(_array) (sizeof(_array) / sizeof(_array[0]))

#define DEFAULT_COAP_SERVER_PORT 5683
#define COAP_MULTICAST_IPV4_ADDR "224.0.1.187"
#define COAP_MULTICAST_IPV6_SITE_LOCAL "ff02::fd"
#define COAP_MULTICAST_IPV6_LINK_LOCAL "ff05::fd"

// We have a second server exposed on private loopback.  We can't collide with
// the public server port because that is bound to ANY_ADDR.  So we allocate
// a different one.
#define PRIVATE_SERVER_PORT 12000
#define PRIVATE_SERVER_ADDR INADDR_LOOPBACK

/**
 * Compare two sockaddr_in structs.  The server needs this to match subscriber
 * endpoints to subscriptions.
 */
static int sockaddr_in_cmp(const void *_a, const void *_b)
{
    const struct sockaddr_in *a = (const struct sockaddr_in *)_a;
    const struct sockaddr_in *b = (const struct sockaddr_in *)_b;
    if (a->sin_addr.s_addr != b->sin_addr.s_addr) {
        return a->sin_addr.s_addr < b->sin_addr.s_addr ? -1 : 1;
    }
    if (a->sin_port != b->sin_port) {
        return a->sin_port < b->sin_port ? -1 : 1;
    }
    return 0;
}

static coap_sub_map_t subs = { .endpoint_cmp = &sockaddr_in_cmp };

/**
 * Emit a log message at level LOG_ERR and exit(EXIT_FAILURE).
 *
 * @param fmt printf format string
 * @paarm ... printf arguments
 */
static void error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ZCOAP_VLOG(ZCOAP_LOG_ERR, fmt, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

static bool exit_request = false;

/**
 * Start and execute the observer subscription polling thread.
 *
 * @param arg unused
 * @return NULL
 */
static void *poll_subscriptions(void *arg)
{
    // Create a timer file descriptor for the subscription polling loop.
    float period = *(float *)arg;
    if (period < 0 || period > UINT_MAX) {
        error("%s: timer period %f is invalid", __func__, (double)period);
    }
    unsigned seconds = period;
    useconds_t usecs = (period - (unsigned)period) * 1e6;
    while (!exit_request) {
        if (seconds) {
            sleep(seconds);
        }
        if (usecs) {
            usleep(usecs);
        }
        coap_publish_all(&subs);
        coap_garbage_collect(&subs);
    }

    // Notify all subscribers we are going down.
    coap_cancel_all(&subs);

    return NULL;
}

/**
 * Spawn the observer subscription polling thread.
 *
 * @param period period on which to poll subscriptions
 * @param thread (out) pthread created
 * @return 0 on success, -1 on error
 */
static int spawn_polling_thread(float *period, pthread_t *thread)
{
    errno = 0;
    if (pthread_create(thread, NULL, &poll_subscriptions, period)) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: pthread_create failed with %d (%s)", __func__, errno, strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * UDP CoAP responder and ack function.  Used as callback from zcoap-server.
 * Injects the passed CoAP message into our UDP stack.  req will have been
 * populated by our dispatch() function with the necessary context information
 * for routing a message back to the requesting client.  In our case, this will
 * be:
 *
 *    * server socket file descriptor
 *    * client sockaddr_in as written by recvfrom
 *
 * Together, we can use these in the sendto function to route the response.
 *
 * @param req CoAP request structure and metadata, including context (socket file descriptor) and route (client sockaddr_in)
 * @param len length of the CoAP response message to send back to the client
 * @param rsp CoAP response message to send back to the client
 */
static void coap_udp_respond(coap_req_data_t * const req, const size_t len, const coap_msg_t *rsp)
{
    int sockfd = req->context;
    const struct sockaddr_in *cli_addr = req->endpoint;
    ssize_t sent = sendto(sockfd, rsp, len, 0, (const struct sockaddr *)cli_addr, sizeof(*cli_addr));
    if (sent < len) {
        error("socket write error on respond");
    }

    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "Sent %ld bytes back to client at addr %s%s%s:%u!\n", sent,
              cli_addr->sin_family == AF_INET6 ? "[" : "",
              inet_ntoa(cli_addr->sin_addr),
              cli_addr->sin_family == AF_INET6 ? "]" : "",
              cli_addr->sin_port);
}

/**
 * Dispatch a received datagram payload into our CoAP server!
 *
 * @param cli_addr client socket address for server responses
 * @param len datagram payload length
 * @parm payload UDP payload - presumed to be a CoAP message structure
 */
static void dispatch(int sockfd, coap_node_t root, struct sockaddr_in *cli_addr, const size_t len, const uint8_t payload[])
{
    coap_req_data_t req = {
        .context = sockfd,
        .endpoint = cli_addr,
        .msg = (const coap_msg_t *)payload,
        .len = len,
        .responder = &coap_udp_respond,
    };
    coap_rx(&req, root);
}

/**
 * On receipt of a signal, set our exit_request flag.  The signal will also
 * interrupt pselect and set errno == EINTR.
 *
 * int signal unused
 */
static void exit_handler(int signal)
{
    exit_request = true;
}

/*
 * Receive a CoAP PDU on the passed socket file descriptor.
 */
static int coap_recv(int fd, coap_node_t root)
{
    uint8_t buf[65535];
    struct sockaddr_in cli_addr =  { 0 };
    socklen_t cli_len = sizeof(cli_addr);
    errno = 0;
    ssize_t received = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&cli_addr, &cli_len);
    if (received < 0) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "recvfrom failed with %d (%s)", errno, strerror(errno));
        return -1;
    }
    if (cli_len > sizeof(cli_addr)) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "recvfrom error - client source address information is truncated");
        return -1;
    }
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "Received %ld bytes, sending to zcoap-server\n", received);
    // Send request into zcoap-server library.
    // coap_udp_respond is called by the library when the response is ready.
    dispatch(fd, root, &cli_addr, received, buf);
    return 0;
}

/**
 * Bind our public server to the IPv4 ANY_ADDR on the standard CoAP port.
 * Also regiter on the CoAP IPv4 multicast address.
 *
 * @param sockfd socket for our public server
 * @return 0 on success, -1 on error
 */
int bind_public_address(int sockfd)
{
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(DEFAULT_COAP_SERVER_PORT),
                                .sin_addr = { .s_addr = INADDR_ANY } };
    // Register on the CoAP broadcast addresses.
    struct ip_mreq mreq = { .imr_multiaddr = { .s_addr = inet_addr(COAP_MULTICAST_IPV4_ADDR) },
                            .imr_interface = { .s_addr = INADDR_ANY } };
    errno = 0;
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "setsockopt failed with %d (%s)", errno, strerror(errno));
        return -1;
    }
    errno = 0;
    if (bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "ERROR on bind - %d (%s)", errno, strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * Bind our public server to the IPv6 ANY_ADDR on the standard CoAP port.
 * Also regiter on the CoAP IPv6 multicast address.
 *
 * @param sockfd socket for our public server
 * @return 0 on success, -1 on error
 */
int bind_public_addressv6(int sockfd)
{
    struct sockaddr_in6 addr = { .sin6_family = AF_INET6, .sin6_port = htons(DEFAULT_COAP_SERVER_PORT),
                                 .sin6_addr = IN6ADDR_ANY_INIT };
    // Turn off IPV6_V6ONLY.  We are using two separate sockets so that we
    // can register on both the IPv4 and IPv6 multicast addressses.
    int v6only = 1;
    errno = 0;
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&v6only, sizeof(v6only))) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "setsockopt failed with %d (%s)", errno, strerror(errno));
        return -1;
    }
    // Register for the CoAP site-local IPv6 address.
    struct ipv6_mreq mreq = { .ipv6mr_multiaddr = 0 };
    if (inet_pton(AF_INET6, COAP_MULTICAST_IPV6_SITE_LOCAL, &mreq.ipv6mr_multiaddr) != 1) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "inet_pton failed for %s", COAP_MULTICAST_IPV6_SITE_LOCAL);
        return -1;
    }
    errno = 0;
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq))) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "setsockopt failed with %d (%s)", errno, strerror(errno));
        return -1;
    }
    // Register for the CoAP link-local IPv6 address.
    if (inet_pton(AF_INET6, COAP_MULTICAST_IPV6_LINK_LOCAL, &mreq.ipv6mr_multiaddr) != 1) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "inet_pton failed for %s", COAP_MULTICAST_IPV6_LINK_LOCAL);
        return -1;
    }
    errno = 0;
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq))) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "setsockopt failed with %d (%s)", errno, strerror(errno));
        return -1;
    }
    // Bind!
    errno = 0;
    if (bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "ERROR on bind - %d (%s)", errno, strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * Bind our private server port its address and port.
 *
 * @param sockfd socket for our public server
 * @return 0 on success, -1 on error
 */
int bind_private_address(int sockfd)
{
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PRIVATE_SERVER_PORT),
                                .sin_addr = { .s_addr = htonl(PRIVATE_SERVER_ADDR) } };
    errno = 0;
    if (bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "ERROR on bind - %d (%s)", errno, strerror(errno));
        return -1;
    }
    return 0;
}

#define CLOSE_SOCKS(_servers) ({\
    for (size_t _i = 0; _i < NELM(_servers); ++_i) {\
        if (_servers[_i].fd >= 0) {\
            close(_servers[_i].fd);\
        }\
    }\
})

int main(int argc, char *argv[])
{
    ZCOAP_LOG(ZCOAP_LOG_INFO, "Starting the ZCoAP POSIX Server...\n");

    // Here, we can decleare as many serverrs here as we like.  We can also map
    // roots to multiple listening sockets.  Simply declare the servers here,
    // open and bind and the server will multplex on pselect.
    enum {
        PRIVATE_SYSFS_SERVER,  // reflects /tmp and portions of sysfs
        PUBLIC_TELEM_SERVER,   // exposes basic server telemetry
        PUBLIC_TELEM_SERVERV6, // exposes basic server telemetry
    };
    struct servers {
        int fd;
        coap_node_t root;
    } servers[] = {
        [PRIVATE_SYSFS_SERVER]  = { .root = private_server_root, .fd = -1 },
        [PUBLIC_TELEM_SERVER]   = { .root = public_server_root,  .fd = -1 },
        [PUBLIC_TELEM_SERVERV6] = { .root = public_server_root,  .fd = -1 },
    };

    // Add our and subscriber map.  It is our choice as to whether our
    // implementation encloses a map-per-tree or a single map.  We choose a
    // single map for simple publishing and garbage collection.  If we were
    // operating a thread pool and wished to reduce tree-to-tree contention,
    // we could instead establish a subscription map for each tree.
    for (size_t i = 0; i < NELM(servers); ++i) {
        servers[i].root.tsubs = &subs;
    }

    // Always initialize the CoAP URI trees before use.  Initialization sorts
    // the trees and executes node-specific initializers.  Multiple calls
    // against a given true are acceptable.  However, each tree must be
    // initialized at least once.
    for (size_t i = 0; i < NELM(servers); ++i) {
        coap_init(servers[i].root);
    }

    // Setup the exit request handler.
    struct sigaction sa;
    sa.sa_handler = &exit_handler;
    // Block every signal during the handler
    sigfillset(&sa.sa_mask);
    // Intercept SIGHUP, SIGINT and SIGTERM
    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        error("Error: cannot handle SIGHUP"); // Should not happen
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        error("Error: cannot handle SIGINT"); // Should not happen
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        error("Error: cannot handle SIGINT"); // Should not happen
    }

    // Create our public inbound server port.
    errno = 0;
    servers[PUBLIC_TELEM_SERVER].fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (servers[PUBLIC_TELEM_SERVER].fd < 0) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "ERROR opening socket - %d (%s)", errno, strerror(errno));
        CLOSE_SOCKS(servers);
        exit(EXIT_FAILURE);
    }
    if (bind_public_address(servers[PUBLIC_TELEM_SERVER].fd) < 0) {
        CLOSE_SOCKS(servers);
        exit(EXIT_FAILURE);
    }

    // Create our public inbound IPv6 server port.
    errno = 0;
    servers[PUBLIC_TELEM_SERVERV6].fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (servers[PUBLIC_TELEM_SERVERV6].fd < 0) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "ERROR opening socket - %d (%s)", errno, strerror(errno));
        CLOSE_SOCKS(servers);
        exit(EXIT_FAILURE);
    }
    if (bind_public_addressv6(servers[PUBLIC_TELEM_SERVERV6].fd) < 0) {
        CLOSE_SOCKS(servers);
        exit(EXIT_FAILURE);
    }

    // Create our local, private inbound server port.
    errno = 0;
    servers[PRIVATE_SYSFS_SERVER].fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (servers[PRIVATE_SYSFS_SERVER].fd < 0) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "ERROR opening socket - %d (%s)", errno, strerror(errno));
        CLOSE_SOCKS(servers);
        exit(EXIT_FAILURE);
    }
    if (bind_private_address(servers[PRIVATE_SYSFS_SERVER].fd) < 0) {
        CLOSE_SOCKS(servers);
        exit(EXIT_FAILURE);
    }

    // Temporarily block signals during pthread creation.
    // pselect will subsequently block and unblock main thread signals for us.
    static sigset_t full_mask, orig_mask;
    errno = 0;
    if (sigfillset(&full_mask)) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: sigfillset failed with %d (%s)", __func__, errno, strerror(errno));
        CLOSE_SOCKS(servers);
        exit(EXIT_FAILURE);
    }
    errno = 0;
    if (sigprocmask(SIG_SETMASK, &full_mask, &orig_mask)) {
        error("%s, line %d: sigprocmask failed with %d (%s)", __func__, __LINE__, errno, strerror(errno));
        CLOSE_SOCKS(servers);
        exit(EXIT_FAILURE);
    }

    // Create a pthread for subscription polling.
    pthread_t polling_thread;
    float polling_period = 5e-3;
    if (spawn_polling_thread(&polling_period, &polling_thread) < 0) {
        CLOSE_SOCKS(servers);
        exit(EXIT_FAILURE);
    }

    // Execute the main server loop.
    int exit_code = 0;
    while (true) {

        if (exit_request) {
            ZCOAP_LOG(ZCOAP_LOG_INFO, "initiating graceful shutdown");
            break;
        }

        fd_set fds;
        FD_ZERO(&fds);
        int max = 0;
        for (size_t i = 0; i < NELM(servers); ++i) {
            FD_SET(servers[i].fd, &fds);
            max = servers[i].fd > max ? servers[i].fd : max;
        }
        errno = 0;
        int ready_fds = pselect(max + 1, &fds, NULL, NULL, NULL, &orig_mask);
        if (ready_fds < 0) {
            if (errno == EINTR) {
                ZCOAP_LOG(ZCOAP_LOG_INFO, "pselect interrupted; initiating graceful shutdown");
                break;
            } else {
                ZCOAP_LOG(ZCOAP_LOG_ERR, "pselect failed with %d (%s)", errno, strerror(errno));
                break;
            }
        }
        for (size_t i = 0; i < NELM(servers); ++i) {
            if (FD_ISSET(servers[i].fd, &fds)) {
                errno = 0;
                if (coap_recv(servers[i].fd, servers[i].root) < 0) {
                    exit_code = EXIT_FAILURE;
                    goto server_cleanup;
                }
            }
        }
    }

    server_cleanup:
    pthread_kill(polling_thread, SIGUSR1);
    pthread_join(polling_thread, NULL);
    CLOSE_SOCKS(servers);
    return exit_code;
}
