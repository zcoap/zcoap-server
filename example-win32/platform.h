/*
 * File:   platform.h

 * Define platform overrides for the Zepto CoAP server here.  Else, defaults
 * in config.h are used.
 */


#ifndef ZCOAP_PLATFORM_H
#define ZCOAP_PLATFORM_H

//#define ZCOAP_MAX_BUF_SIZE 64
//#define ZCOAP_MAX_PAYLOAD_OPTS 32
//#define ZCOAP_MALLOC malloc
//#define ZCOAP_CALLOC calloc
//#define ZCOAP_REALLOC realloc
//#define ZCOAP_FREE free
//#define ZCOAP_MEMCPY memcpy
//#define ZCOAP_MEMMOVE memmove
//#define ZCOAP_MEMSET memset
//#define ZCOAP_SNPRINTF zsnprintf
//#define ZCOAP_VSNPRINTF zvsnprintf

//Populate these methods if you want the zcoap-server to lock the helper (ie coap_get_int) when accessing the .data reference.
//#define ZCOAP_LOCK(void) ({ })
//#define ZCOAP_UNLOCK(void) ({ })

//#define ZCOAP_DOUBLE double
//#define SUPPRESS_ZCOAP_EXTENSIONS
//#define ZCOAP_HTONL htonl
//#define ZCOAP_HTONS htons
//#define ZCOAP_NTOHL ntohl
//#define ZCOAP_NTOHS ntohs

/**
 * Implementation may define a variadic debug function in order to enable debug
 * logging from the Zepto CoAP server.
 */
//#define ZCOAP_DEBUG(format, args...) fprintf (stderr, format, args)


#endif /* ZCOAP_PLATFORM_H */
