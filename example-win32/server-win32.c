
#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

//Example socket servercode taken from 
//https://docs.microsoft.com/en-us/windows/win32/winsock/complete-server-code

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 1020

//Use default coap port per rfc
#define DEFAULT_PORT "5683"

//Include the server
#include "../src/zcoap-server.h"

//Include example URIs
#include "example-server-win32-endpoints.h"

// Example tree
// /.well-known/core
// /telemetry/temperature/
// /telemetry/temperature/max
// /telemetry/digits
// /telemetry/name

static const coap_node_t* root_children[] = { &wellknown_uri, &telemetry_uri, NULL };
static const coap_node_t root = { .children = root_children };

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
    const struct SOCKET *cli_sock = req->route;

	// Echo the buffer back to the sender
    int iSendResult = send(ClientSocket, rsp, iResult, 0);

    if (iSendResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    printf("Bytes sent: %d\n", iSendResult);
}

/**
 * Dispatch a received datagram payload into our CoAP server!
 *
 * @param cli_addr client socket address for server responses
 * @param len datagram payload length
 * @parm payload UDP payload - presumed to be a CoAP message structure
 */
static void dispatch(const SOCKET *client_sock, const size_t len, const uint8_t payload[])
{
    // Make a request
    coap_req_data_t req = {
        // This is the socket file descriptor, but it's not needed in this win32 example
		// Instead, we will pass through a pointer to the ClientSocket which we will send a response on
        .context = 0,
        // The address we should respond to
        .route = client_sock,
        // Bytes of the cCoAP payload, including the UDP frame
        .msg = (const coap_msg_t *)payload,
        // Number of bytes in the payload
        .len = len,
        // Hold function to call to respond to the message
        .responder = &coap_udp_respond,
    };

    // Submit the request with the reference to the root of the tree built above
    coap_rx(&req, &root);
}

int __cdecl main(void)
{
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    int iSendResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    printf("Listening on port %d\n", DEFAULT_PORT);
    
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);

    // Receive until the peer shuts down the connection
    do {

        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);

        if (iResult > 0) {
            printf("Bytes received: %d\n", iResult);

            // Send new data into CoAP
            dispatch(&ClientSocket, iResult, recvbuf);
        }
        else if (iResult == 0) {
            printf("Connection closing...\n");
        }
        else {
            printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }

    } while (iResult > 0);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}


