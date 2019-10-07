
// Socket server adapted from 
// http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/server.c

#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

//#include "zcoap-server.h"

//static const coap_node_t core = { .name = "core", .GET = &dump_coap_tree };
//static const coap_node_t *wellknown_children[] = { &core, NULL };
//static const coap_node_t wellknown = { .name = ".well-known", .children = wellknown_children  };
//static const coap_node_t *root_children[] = { &wellknown, NULL };
//static const coap_node_t root = { .children = root_children };

#define DEFAULT_PORT 5683

void error(char *msg)
{
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sockfd, newsockfd, clilen;
    int portno = DEFAULT_PORT;

    char buffer[1024];

    struct sockaddr_in serv_addr, cli_addr;
    
    int n;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
       error("ERROR opening socket");
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    
    if (bind(sockfd, (struct sockaddr *) &serv_addr,
             sizeof(serv_addr)) < 0)
    {
        error("ERROR on binding");
    }

    listen(sockfd, 5);
    
    clilen = sizeof(cli_addr);
    
    printf("Listening on port %d\n", (int)DEFAULT_PORT);

    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    
    if (newsockfd < 0)
    {
         error("ERROR on accept");
    }
    
    bzero(buffer, 256);
    
    n = read(newsockfd, buffer, 255);
    
    if (n < 0) error("ERROR reading from socket");
    {
        printf("Received bytes: %s\n", buffer);
    }

    n = write(newsockfd, "I got your bytes!", 18);
    
    if (n < 0) 
    {
        error("ERROR writing to socket");
    }
    
    return 0; 
}