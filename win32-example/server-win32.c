

#include<stdio.h>
#include<winsock2.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library

#define BUFLEN 512	//Max length of buffer
#define PORT 5683	//The port on which to listen for incoming data

//
//Include the server
#include "../src/zcoap-server.h"

//Include example URIs
#include "server-win32-endpoints.h"

// Example tree
// /.well-known/core
// /telemetry/temperature/
// /telemetry/temperature/max
// /telemetry/digits
// /telemetry/name

//A coap client would send a request, for example to coap://127.0.0.1:5689/.well-known/core

static const coap_node_t* root_children[] = { &wellknown_uri, &telemetry_uri, NULL };
static const coap_node_t root = { .children = root_children };

//Winsock2 socket resources for application to list on a UDP socket.
SOCKET receive_sock;
struct sockaddr_in server, si_other;
int slen, recv_len;
char buf[BUFLEN];
WSADATA wsa;

typedef struct CoapTransaction_t {
    SOCKET rxSocket;
    struct sockaddr_in* rxAddress;
    int socketaddr_length;
}coap_transaction;

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
    const struct CoapTransaction_t *ct = req->endpoint;

    printf("    Coap Response - id = %d, code detail = %d, code class = %d, type = %d, len = %d\n",
        rsp->msg_ID, rsp->code.code_detail, 
        rsp->code.code_class, rsp->type,
        len);
    
    //Send coap response to sender
    int send_result = sendto(ct->rxSocket, rsp, len, 0, 
        (struct sockaddr*)ct->rxAddress, 
        ct->socketaddr_length);

    if (send_result == SOCKET_ERROR){
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(&ct->rxSocket);
        WSACleanup();
        return 1;
    }

    printf("Bytes sent: %d\n", send_result);
}

/**
 * Dispatch a received datagram payload into our CoAP server!
 *
 * @param cli_addr client socket address for server responses
 * @param len datagram payload length
 * @parm payload UDP payload - presumed to be a CoAP message structure
 */
static void dispatch(const SOCKET *receive_sock, const size_t len, const uint8_t payload[])
{
    // Make a request
    coap_req_data_t req = {
        // This is the socket file descriptor, but it's not needed in this win32 example
		// Instead, we will pass through a pointer to the ClientSocket which we will send a response on
        .context = 0,
        // The address we should respond to
        .endpoint = receive_sock,
        // Bytes of the cCoAP payload, including the UDP frame
        .msg = (const coap_msg_t *)payload,
        // Number of bytes in the payload
        .len = len,
        // Hold function to call to respond to the message
        .responder = &coap_udp_respond,
    };

    // Submit the request with the reference to the root of the tree built above
    coap_rx(&req, root);
}

int main()
{
    coap_init(root); // must always init our tree before use!

    slen = sizeof(si_other);

    //Initialise winsock
    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2, 2), & wsa) != 0)
    {
        printf(" Failed.Error Code : % d " , WSAGetLastError());
        exit(EXIT_FAILURE);
    }
    printf("Initialised.\n");

    //Create a socket
    if ((receive_sock = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
    {
        printf(" Could not create socket : % d ", WSAGetLastError());
    }
    printf(" Socket created.\n ");

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    //Bind
    if (bind(receive_sock, (struct sockaddr*) & server, sizeof(server)) == SOCKET_ERROR)
    {
        printf(" Bind failed with error code : % d ", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
    puts(" Bind done ");

    //keep listening for data
    while (1)
    {
        printf(" Waiting for data... ");
        fflush(stdout);

        //clear the buffer by filling null, it might have previously received data
        memset(buf, '\0', BUFLEN);

        //try to receive some data, this is a blocking call
        if ((recv_len = recvfrom(receive_sock, buf, BUFLEN, 0, (struct sockaddr*) &si_other, &slen)) == SOCKET_ERROR)
        {
            printf("recvfrom() failed with error code : % d ", WSAGetLastError());
            exit(EXIT_FAILURE);
        }

        //print details of the client/peer and the data received
        printf("Received packet from % s: % d\n " , inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
        printf("Data: % s\n ", buf);

        printf("Sending to zcoap-server...\n");

        //coap_transaction is just a struct we use to keep track of the transaction as we
        //pass the data into zcoap-server.  We need this data so that the response function
        //is able to send data back to the socket recipent
        coap_transaction ct;
        ct.rxAddress = &si_other;
        ct.rxSocket = receive_sock;
        ct.socketaddr_length = slen;

        // Send new data into zcoap-server
        dispatch(&ct, recv_len, buf);

        printf("CoAP transaction completed!\r\n");
    }

    closesocket(receive_sock);
    WSACleanup();

    return 0;
}
