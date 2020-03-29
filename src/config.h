/*
 * File:   config.h
 * Author: Michael Sandstedt
 *
 * Configure the zcoap-server with all defaults not already
 * defined in platform.h.
 *
 * Created on September 12th, 2019
 */

#ifndef ZCOAP_CONFIG_H
#define ZCOAP_CONFIG_H

#include <platform.h>

#ifndef ZCOAP_MAX_BUF_SIZE
/**
 * ZCOAP_MAX_BUF_SIZE
 *
 * Maximum buffer size for incoming ASCII payloads and path segments.

 * Note, this doesn't affect the allowed size of the response buffer.
 * For example, if the response is a long byte array as you might see
 * when using COAP_FMT_TEXT or COAP_FMT_XML, we call malloc as needed
 * for the response buffer.
 *
 * If you're on a microcontroller and not using __GNUC__, be aware,
 * messages will end up creating buffers on the stack of this size for each
 * level of the coap tree.  So if your tree, at its max, is 6 levels 
 * deep, your stack should support a buffer allocation
 * of 6 * ZCOAP_MAX_BUF_SIZE.
 */
#define ZCOAP_MAX_BUF_SIZE 64
#endif /* ZCOAP_MAX_BUF_SIZE */

#ifndef ZCOAP_MAX_PAYLOAD_OPTS
/**
 * ZCOAP_MAX_PAYLOAD_OPTS
 *
 * We will be popping arrays of payload option pointers onto the stack. We
 * therefore need to define a maximum number of option entries for incoming
 * payloads.
 */
#define ZCOAP_MAX_PAYLOAD_OPTS 32
#endif /* ZCOAP_MAX_PAYLOD_OPTS */

#ifndef ZCOAP_MALLOC
/**
 * ZCOAP_MALLOC and family
 *
 * The zcoap-server dynamically allocates memory.  What dynamic
 * allocation family should we use?  By default, we use the stdlib functions.
 */
#include <stdlib.h>
#define ZCOAP_MALLOC malloc
#define ZCOAP_CALLOC calloc
#define ZCOAP_REALLOC realloc
#define ZCOAP_FREE free
#endif /* ZCOAP_MALLOC */

#ifndef ZCOAP_ALLOCA
/**
 * ZCOAP_ALLOCA
 *
 * PDU contruction immediately prior to transmission from coap_rsp requires
 * very temporary allocation of potentially large buffers.  For this purpose,
 * alloca can be ideal.  But on platforms where this is not available or for
 * which popping large amounts of data on the stack is not acceptable,
 * malloc/free must be used instead.
 *
 * By default we use these.  But if implementations can benefit, it is
 * encouraged that ZCOAP_ALLOCA be defined in platform.h.
 */
#define ZCOAP_ALLOCA ZCOAP_MALLOC
#define ZCOAP_ALLOCA_FREE ZCOAP_FREE
#else
/* If we have a real alloca, we don't need a symmetric free. Thus, no-op. */
#define ZCOAP_ALLOCA_FREE(_buf)
#endif

#ifndef ZCOAP_MEMCPY
/**
 * ZCOAP_MEMCPY
 *
 * What memory copy function should the zcoap-server use?  By default, we
 * use the string.h function.
 */
#include <string.h>
#define ZCOAP_MEMCPY memcpy
#endif /* ZCOAP_MEMCPY */

#ifndef ZCOAP_MEMMOVE
/**
 * ZCOAP_MEMMOVE
 *
 * What memory move function should the zcoap-server use?  By default, we
 * use the string.h function.
 */
#include <string.h>
#define ZCOAP_MEMMOVE memmove
#endif /* ZCOAP_MEMMOVE */

#ifndef ZCOAP_MEMSET
/**
 * ZCOAP_MEMSET
 *
 * What memory set function should the zcoap-server use?  By default, we
 * use the string.h function.
 */
#include <string.h>
#define ZCOAP_MEMSET memset
#endif /* ZCOAP_MEMSET */

#ifndef ZCOAP_SNPRINTF
/**
 * ZCOAP_SNPRINTF
 *
 * What snprintf shoudl the zcoap-server use?  By default, for speed and
 * to achieve reentrance on platforms where this is NOT assured, we use our
 * own!
 */
#include "zsnprintf.h"
#define USE_ZCOAP_SNPRINTF
#define ZCOAP_SNPRINTF zsnprintf
#define ZCOAP_VSNPRINTF zvsnprintf
#endif /* ZCOAP_SNPRINTF */

#ifndef ZCOAP_LOCK
/**
 * ZCOAP_LOCK
 *
 * The zcoap-server utility GET and PUT methods will access platform memory.
 * If operating in a multi-threaded environment, the zcoap-server must
 * protect access to this memory.  This is achieved with calls to the
 * ZCOAP_LOCK and ZCOAP_UNLOCK macros.  But zcoap is portable has no notion
 * of YOUR platform.  Thus, if YOU wish to use zcoap in a multi-threaded
 * environment, YOU must define locking/unlocking functions.  Else, zcoap
 * uses no-op macros for these.
 */
#define ZCOAP_LOCK(void){}
#define ZCOAP_UNLOCK(void){}
#endif /* ZCOAP_LOCK */

#ifndef ZCOAP_DOUBLE
/**
 * ZCOAP_DOUBLE
 *
 * Some embedded platforms may use the IEEE-754 single-precision float for the
 * double type.  This can be true, for instance, for dsPIC33/PIC24 + XC16.  On
 * platforms with no FPU, this can be expedient, as without this, a lot of
 * math may be indadvertantly performed in double-precision, and at great
 * expense.
 *
 * Consider: all floating point constants in C not explicitly declared
 * single-precision by appending 'f' are implicitly double-precision.
 *
 * But for our purposes in the zcoap-server, when we say 'double', we
 * really do mean IEEE-754 double-precision and may be using this format
 * on the wire.  Thus we provide this macro logic.  The zcoap-server
 * config will attempt to auto-detect this and configure correctly for YOUR
 * platform.  In testing, this has worked everywhere we've thought to check.
 * But implementations may override this by defining their own ZCOAP_DOUBLE.
 */
#include <float.h>

#ifdef __GNUC__

    #if (__DBL_MANT_DIG__ != 53 && __LDBL_MANT_DIG__ == 53)
        #define ZCOAP_DOUBLE long double
        #define RESPONSE_FMT_DOUBLE "%.8Lg"
    #elif (__DBL_MANT_DIG__ != 53)
        #error unable find a native 64-bit type for the zcoap double!
    #else
        #define ZCOAP_DOUBLE double
        #define RESPONSE_FMT_DOUBLE "%.8g"
    #endif

#else

    #if (DBL_MANT_DIG != 53 && LDBL_MANT_DIG == 53)
        #define ZCOAP_DOUBLE long double
        #define RESPONSE_FMT_DOUBLE "%.8Lg"
    #elif (DBL_MANT_DIG != 53)
        #error unable find a native 64-bit type for the zcoap double!
    #else
        #define ZCOAP_DOUBLE double
        #define RESPONSE_FMT_DOUBLE "%.8g"
    #endif

#endif

#endif /* ZCOAP_DOUBLE */

#endif /* ZCOAP_CONFIG_H */
