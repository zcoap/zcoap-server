
// Socket server adapted from
// http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/server.c

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../src/zcoap-server.h"
#include "example-server-linux-fs.h"
#include "example-server-linux-telemetry.h"

// The filesystem generator, coap_fs_gen, is very cool!  We can mount and
// reflect any node of the filesystem at any node in our CoAP URI tree.
// coap_fs_gen is recursive, so really does work just as a mount point.
//
// Make sure, however, anything 'mounted' has proper permissions set.  Anything
// accessible to the server and reflected by coap_fs_gen will be accessible to
// clients.
//
// To provide some interesting data for our *example* server, lets mount these:
//
// /tmp -> coap:///tmp
// /sys/power -> coap://telemetry/power

static const coap_node_t tmp_uri = { .name = "tmp", .gen = &coap_fs_gen, .metadata = "/tmp" };
static const coap_node_t *root_children[] = { &wellknown_uri, &tmp_uri, &telemetry_uri, NULL };
static const coap_node_t root = { .children = root_children };

#define DEFAULT_PORT 5683

static void error(char *msg)
{
    perror(msg);
    exit(1);
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
    const int sockfd = req->context;
    const struct sockaddr_in *cli_addr = req->route;
    ssize_t sent = sendto(sockfd, rsp, len, MSG_CONFIRM, (const struct sockaddr *)cli_addr, sizeof(*cli_addr));
    if (sent < len)
    {
        error("socket write error on respond");
    }
}

/**
 * Dispatch a received datagram payload into our CoAP server!
 *
 * @param cli_addr client socket address for server responses
 * @param len datagram payload length
 * @parm payload UDP payload - presumed to be a CoAP message structure
 */
static void dispatch(int sockfd, const struct sockaddr_in *cli_addr, const size_t len, const uint8_t payload[])
{
    coap_req_data_t req = {
        .context = sockfd,
        .route = cli_addr,
        .msg = (const coap_msg_t *)payload,
        .len = len,
        .responder = &coap_udp_respond,
    };
    coap_rx(&req, &root);
}

int main(int argc, char *argv[])
{
    coap_init(&root); // must always init our tree before use!

    const int portno = DEFAULT_PORT;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
       error("ERROR opening socket");
    }

    struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(portno),
                                     .sin_addr = { .s_addr = INADDR_ANY } };
    if (bind(sockfd, (const struct sockaddr *)&serv_addr,
             sizeof(serv_addr)) < 0)
    {
        error("ERROR on binding");
    }

    while (1)
    {
        ssize_t pending = recv(sockfd, NULL, 0, MSG_PEEK | MSG_TRUNC);
        if (pending < 0)
        {
            error("ERROR reading from socket");
        }
        uint8_t buf[pending];
        struct sockaddr_in cli_addr =  { 0 };
        socklen_t cli_len = sizeof(cli_addr);
        ssize_t received = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&cli_addr, &cli_len);
        if (received != pending)
        {
            error("ERROR reading from socket - pending and received counts do not match");
        }
        if (cli_len > sizeof(cli_addr))
        {
            error("recvfrom error - client source address information is truncated");
        }
        dispatch(sockfd, &cli_addr, received, buf);
    }
    return 0;
}
