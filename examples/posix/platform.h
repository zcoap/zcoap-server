/*
 * File:   platform.h
 * Author: Michael Sandstedt
 *
 * Define platform overrides for the ZCoAP server here.  Else, defaults
 * in config.h are used.
 */


#ifndef ZCOAP_PLATFORM_H
#define ZCOAP_PLATFORM_H

#include <netinet/in.h>
#include <pthread.h>
typedef struct sockaddr_in coap_endpoint_t;

#define ZCOAP_MAX_BUF_SIZE 256 /* from default 64 to support our fs max filename segment, 255 bytes */
#define ZCOAP_MAX_PAYLOAD_OPTS 64 /* library has 32 as default, but we have lots of memory */
#define ZCOAP_ALLOCA alloca /* alloca can give us a big speed up in coap_rsp; for partability, zcoap-server doesn't use it by default, but we have it and should use it. */

// We want to show off high-frequency observation.
// Give us big NSTART and drop thresholds.
#define ZCOAP_SUB_NSTART_BITS 8
#define ZCOAP_SUB_DROP_THRESH 100

/*
 * We are multithreaded.  Give the zcoap server some locking primitives.
 */
typedef pthread_mutex_t coap_lock_t;
#define ZCOAP_LOCK(_lock) ({\
    pthread_mutex_lock(_lock);\
})
#define ZCOAP_UNLOCK(_lock) ({\
    pthread_mutex_unlock(_lock);\
})

#include <syslog.h>
#define ZCOAP_VLOG(_level, _fmt, _ap) ({\
    if ((_level) <= ZCOAP_LOG_ERR) {\
        vsyslog(_level, _fmt, _ap);\
    }\
})
#define ZCOAP_LOG(_level, _args...) ({\
    if ((_level) <= ZCOAP_LOG_ERR) {\
        syslog(_level, _args);\
    }\
})

#define ZCOAP_ASSERT(_condition) ({\
    if (!(_condition)) {\
        ZCOAP_LOG(ZCOAP_LOG_CRIT, "Assertion failed, function %s, line %d.", __func__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
})
#endif /* ZCOAP_PLATFORM_H */
