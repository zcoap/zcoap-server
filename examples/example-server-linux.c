
// Socket server adapted from
// http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/server.c

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../src/zcoap-server.h"

static const coap_node_t *root_children[] = { &wellknown_uri, NULL };
static const coap_node_t root = { .children = root_children };

#define DEFAULT_PORT 5683

void error(char *msg)
{
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
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
        socklen_t clilen = sizeof(cli_addr);
        ssize_t received = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&cli_addr, &clilen);
        if (received != pending)
        {
            error("ERROR reading from socket - pending and received counts do not match");
        }
        if (clilen > sizeof(cli_addr))
        {
            error("recvfrom error - client source address information is truncated");
        }
    }
    return 0;
}
