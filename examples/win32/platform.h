/*
 * File:   platform.h

 * Define platform overrides for the ZCoAP server here.  Else, defaults
 * in config.h are used.
 */


#ifndef ZCOAP_PLATFORM_H
#define ZCOAP_PLATFORM_H

#include <winsock2.h>
typedef struct CoapTransaction_t {
    SOCKET rxSocket;
    struct sockaddr_in rxAddress;
    int socketaddr_length;
} coap_transaction;
typedef coap_transaction coap_endpoint_t;

//#define ZCOAP_MAX_BUF_SIZE 64
//#define ZCOAP_MAX_PAYLOAD_OPTS 32
//#define ZCOAP_MALLOC malloc
//#define ZCOAP_CALLOC calloc
//#define ZCOAP_REALLOC realloc
//#define ZCOAP_FREE free
//#define ZCOAP_MEMCPY memcpy
//#define ZCOAP_MEMMOVE memmove
//#define ZCOAP_MEMSET memset
//#define ZCOAP_SNPRINTF snprintf
//#define ZCOAP_VSNPRINTF vsnprintf

//Populate these methods if you want the zcoap-server to lock the helper (ie coap_get_int) when accessing the .data reference.
//#define ZCOAP_LOCK(void) ({ })
//#define ZCOAP_UNLOCK(void) ({ })

//#define ZCOAP_DOUBLE double
//#define ZCOAP_HTONL htonl
//#define ZCOAP_HTONS htons
//#define ZCOAP_NTOHL ntohl
//#define ZCOAP_NTOHS ntohs

/**
 * Implementation may define a variadic debug function in order to enable debug
 * logging from the ZCoAP server.
 */
#define ZCOAP_DEBUG(format, args) fprintf (stderr, format, args)


//This is a fix for some errors when using MSVC:
//zcoap-server.lib(zcoap-server.c.obj) : 
//  error LNK2019: unresolved external symbol _strncasecmp referenced in function _coap_parse_req_bool
//zcoap-server.lib(zsnprintf.c.obj) : 
//  error LNK2019: unresolved external symbol _isnanl referenced in function _zftoal
#ifdef _MSC_VER 
 //not #if defined(_WIN32) || defined(_WIN64) because we have strncasecmp in mingw
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

#endif /* ZCOAP_PLATFORM_H */
