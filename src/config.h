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

#define ZCOAP_LOG_EMERG   0
#define ZCOAP_LOG_ALERT   1
#define ZCOAP_LOG_CRIT    2
#define ZCOAP_LOG_ERR     3
#define ZCOAP_LOG_WARNING 4
#define ZCOAP_LOG_NOTICE  5
#define ZCOAP_LOG_INFO    6
#define ZCOAP_LOG_DEBUG   7
#ifndef ZCOAP_LOG
/**
 * Implementions may define a platform-specific logging function.
 * If none is defined, ZCOAP_LOG is a no-op.
 */
#define ZCOAP_LOG(_level, ...){}
#define ZCOAP_VLOG(_level, _fmt, _ap){}
#endif /*ZCOAP_LOG */

#ifndef ZCOAP_ASSERT
/**
 * Implementation may define a custom assert macro.
 * Else, the standard libray macro is used.
 */
#include <assert.h>
#define ZCOAP_ASSERT assert
#endif /* ZCOAP_ASSERT */

#ifndef ZCOAP_MAX_BUF_SIZE
/**
 * ZCOAP_MAX_BUF_SIZE
 *
 * Maximum buffer size for incoming ASCII-encoded primititives, path
 * segments, and other things we may frequently allocate on the stack.

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
 * We will be pushing arrays of payload option pointers onto the stack. We
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
 * PDU construction immediately prior to transmission from coap_rsp requires
 * very temporary allocation of potentially large buffers.  For this purpose,
 * alloca can be ideal.  But on platforms where this is not available or for
 * which pushing large amounts of data on the stack is not acceptable,
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
 * What snprintf should the zcoap-server use?  By default, for speed and
 * to achieve reentrance on platforms where this is NOT assured, we use our
 * own!
 */
#include "../zsnprintf/zsnprintf.h"
#define ZCOAP_SNPRINTF zsnprintf
#define ZCOAP_VSNPRINTF zvsnprintf
#endif /* ZCOAP_SNPRINTF */

#ifndef ZCOAP_LOCK
/**
 * Implementation-specific synchronization primitives.  If our CoAP server is
 * multithreaded, we require mutex lock / unlock for reads and writes to nodes
 * and management of our observable subscription tables.  An implementation may
 * define these locking primitives for thread-safe operation.  Else, they are
 * no-ops.
 *
 * Note that only library getters and setters call the locks by default.
 * Implementation-defined method functions must also call the lock macros or
 * otherwise manage synchronization on their own.
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

#ifndef ZCOAP_MAX_SUBSCRIBERS
/**
 * We must limit total number of subscriber endpoints to keep subscription
 * map memory footprint reasonable.
 */
#define ZCOAP_MAX_SUBSCRIBERS 32
#endif /* ZCOAP_MAX_SUBSCRIBERS */

#ifndef ZCOAP_MAX_SUBSCRIPTIONS
/**
 * We must limit total number of subscriber endpoints to keep subscription
 * map memory footprint reasonable.
 */
#define ZCOAP_MAX_SUBSCRIPTIONS 64
#endif /* ZCOAP_MAX_SUBSCRIPTIONS */

#ifndef ZCOAP_SUB_ID_BITS
/**
 * The ZCoAP server supports a predefined number of subscriptions per client
 * response route.  This is because we must correlate confirmable observation
 * response ACKs to subscriptions based solely upon client endpoint and ACK
 * message ID.  To do so, we use some of the message ID bits to map ACks to
 * per-route subscriptions.  The number of bits we allocate for this purpose
 * determine the number of subscriptions-per-route we can support.  The
 * remaining bits are used for per-subscription windowing.  The more bits we
 * have for per-subscription windowing, the more simultaneous in-flight
 * responses we can support in each subscription transaction window.
 *
 * A typical usage is UDP over IP.  In this scenario, a client will usually
 * have many outbound ports available across which traffic can be spread if
 * necessary.  This in effect gives such a client access to multiple response
 * endpoints if desired.  The number of subscriptions per response endpoint
 * does not therefore impose a hard functional limitation.  However, the
 * per-subscription window does.  If we wish to expose high-frequency,
 * high-throughput observables, we have a hard constraint at the upper end
 * where maximum number of updates per subscription per second is:
 *
 *   updates / sec = per-subscription-window / round-trip-time
 *
 * We therefore, by default, allocate more bits for each subscription window
 * than we do for the subscription ID.  As a concrete example, if we have:
 *
 * ZCOAP_SUB_ID_BITS = 6
 * ZCOAP_SUB_NSTART_BITS = 16 - ZCOAP_SUB_ID_BITS = 10
 *
 * Maximum subscriptions-per-route = 2^6 = 64
 * Maximum per-subscription window = 2^10 = 1024
 *
 * With a very modest client-server round-trip-time of 1-second, this gives us
 * up to 1024 observation udpates per second.  That's pretty good!
 *
 * Note that for each subscription ID within the ZCOAP_SUB_ID_BITS space, we
 * require a state bit in each subscriber object to track subscription ID
 * allocation.  Space required per subscriber is:
 *
 * bytes per subscriber object = 1 << (ZCOAP_SUB_ID_BITS - 3)
 */
#define ZCOAP_SUB_ID_BITS 6
#endif /* ZCOAP_SUB_ID_BITS */

#ifndef ZCOAP_SUB_NSTART_BITS
/**
 * Set our window size for outgoing observer responses.  Higher throughput
 * requires higher NSTART.  On the other hand, congestion concerns may warrant
 * limiting NSTART.
 *
 * To compute subscription NSTART:
 *
 * NSTART = (1 << ZCOAP_SUB_NSTART_BITS) - 1
 */
#define ZCOAP_SUB_NSTART_BITS 5
#endif /* ZCOAP_SUB_NSTART_BITS */

#ifndef ZCOAP_SUB_DROP_THRESH
/**
 * For observables, we need a window-size threshold for which we should
 * assume the observer has disappeared.  If our garbage collector finds that
 * the observer has this many ACKs outstanding, we will assume the observer
 * has disappeared and de-register the subscription.
 *
 * If an implementaiton exposes high-frequency observables, this can be
 * increased to acount for endpoint link round-trip-time.
 *
 * Note that drop threshold must be strictly less than NSTART.
 */
#define ZCOAP_SUB_DROP_THRESH 20
#endif /* ZCOAP_SUB_DROP_THRESH */

#endif /* ZCOAP_CONFIG_H */
