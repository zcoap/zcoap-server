/*
 * File:   zcoap-server.h
 * Author: Michael Sandstedt
 *
 * Created on March 31, 2018, 1:24 PM
 */

#ifndef ZCOAP_SERVER_H
#define ZCOAP_SERVER_H

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "config.h"

#define COAP_PORT 5683
#define COAPS_PORT 5684
#define COAP_MULTICAST_IPV4_ADDR "224.0.1.187"
#define COAP_MULTICAST_IPV6_SITE_LOCAL "ff02::fd"
#define COAP_MULTICAST_IPV6_LINK_LOCAL "ff05::fd"

typedef enum coap_type_e {
    COAP_TYPE_CONFIRMABLE = 0,
    COAP_TYPE_NON_CONFIRMABLE = 1,
    COAP_TYPE_ACK = 2,
    COAP_TYPE_RESET = 3,
} coap_type_t;

enum {
    COAP_REQ = 0,
    COAP_SUCCESS = 2,
    COAP_CLIENT_ERR = 4,
    COAP_SERVER_ERR = 5,
};

enum {
    COAP_REQ_METHOD_GET = 1,
    COAP_REQ_METHOD_POST = 2,
    COAP_REQ_METHOD_PUT = 3,
    COAP_REQ_METHOD_DEL = 4,
};

enum {
    COAP_SUCCESS_DEL = 2,
    COAP_SUCCESS_VALID = 3,
    COAP_SUCCESS_CHANGED = 4,
    COAP_SUCCESS_CONTENT = 5,
};

enum {
    COAP_CLIENT_ERR_BAD_REQ = 0,
    COAP_CLIENT_ERR_UAUTH = 1,
    COAP_CLIENT_ERR_BAD_OPT = 2,
    COAP_CLIENT_ERR_FORBIDDEN = 3,
    COAP_CLIENT_ERR_NOT_FOUND = 4,
    COAP_CLIENT_ERR_METHOD_NOT_ALLOWED = 5,
    COAP_CLIENT_ERR_NO_ACCEPT = 6,
    COAP_CLIENT_ERR_PRECOND_FAILED = 12,
    COAP_CLIENT_ERR_REQ_TOO_LARGE = 13,
    COAP_CLIENT_ERR_CONTENT_FMT = 15,
};

enum {
    COAP_SERVER_ERR_INTERNAL = 0,
    COAP_SERVER_ERR_NOT_IMPLEMENTED = 1,
    COAP_SERVER_ERR_BAD_GATEWAY = 2,
    COAP_SERVER_ERR_SERVICE_UNAVAIL = 3,
    COAP_SERVER_ERR_GATEWAY_TIMEOUT = 4,
    COAP_SERVER_ERR_NO_PROXY_SUPPORT = 5,
};

#define COAP_CODE_BITS_CLASS 3
#define COAP_CODE_BITS_DETAIL 5
#define COAP_CODE_MASK_CLASS ((1U << COAP_CODE_BITS_CLASS) - 1)
#define COAP_CODE_MASK_DETAIL ((1U << COAP_CODE_BITS_DETAIL) - 1)
typedef uint8_t coap_code_t;
#define COAP_CODE(_class, _detail) ((((_class) & COAP_CODE_MASK_CLASS) << COAP_CODE_BITS_DETAIL) | ((_detail) & COAP_CODE_MASK_DETAIL))
#define COAP_CODE_TO_CLASS(_code) (((_code) >> COAP_CODE_BITS_DETAIL) & COAP_CODE_MASK_CLASS)

enum {
    COAP_OPT_IF_MATCH = 1,
    COAP_OPT_URI_HOST = 3,
    COAP_OPT_ETAG = 4,
    COAP_OPT_IF_NONE_MATCH = 5,
    COAP_OPT_OBSERVE = 6,
    COAP_OPT_URI_PORT = 7,
    COAP_OPT_LOCATION_PATH = 8,
    COAP_OPT_PATH = 11,
    COAP_OPT_CONTENT_FMT = 12,
    COAP_OPT_MAX_AGE = 14,
    COAP_OPT_URI_QUERY = 15,
    COAP_OPT_ACCEPT = 17,
    COAP_OPT_LOCATION_QUERY = 20,
    COAP_OPT_PROXY_URI = 35,
    COAP_OPT_PROXY_SCHEME = 39,
    COAP_OPT_SIZE1 = 60,
};

typedef enum coap_content_format_e {
    // See registry here: https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats
    COAP_FMT_TEXT = 0,
    COAP_FMT_COSE_ENCRYPT0 = 16,
    COAP_FMT_COSE_MAC0 = 17,
    COAP_FMT_COSE_SIGN1 = 18,
    COAP_FMT_LINK = 40,
    COAP_FMT_XML = 41,
    COAP_FMT_STREAM = 42,
    COAP_FMT_EXI = 47,
    COAP_FMT_JSON = 50,
    COAP_FMT_JSON_PATCH = 51,
    COAP_FMT_JSON_MERGE_PATCH = 52,
    COAP_FMT_CBOR = 60,
    COAP_FMT_CWT = 61,
    COAP_FMT_MULTIPART_CORE = 62,
    COAP_FMT_CBOR_SEQ = 63,
    COAP_FMT_COSE_ENCRYPT = 96,
    COAP_FMT_COSE_MAC = 97,
    COAP_FMT_COSE_SIGN = 98,
    COAP_FMT_COSE_KEY = 101,
    COAP_FMT_COSE_KEY_SET = 102,
    COAP_FMT_SENML_JSON = 110,
    COAP_FMT_SENSML_JSON = 111,
    COAP_FMT_SENML_CBOR = 112,
    COAP_FMT_SENSML_CBOR = 113,
    COAP_FMT_SENML_EXI = 114,
    COAP_FMT_SENSML_EXI = 115,
    COAP_FMT_COAP_GROUP_JSON = 256,
    COAP_FMT_DOTS_CBOR = 271,
    COAP_FMT_PKCS7_MIME_SMIME_TYPE_SERVER_GENERATED_KEY = 280,
    COAP_FMT_PKCS7_MIME_SMIME_TYPE_CERTS_ONLY = 281,
    COAP_FMT_PKCS7_MIME_SMIME_TYPE_CMD_REQUEST = 282,
    COAP_FMT_PKCS7_MIME_SMIME_TYPE_CMC_RESPONSE = 283,
    COAP_FMT_PKCS8 = 284,
    COAP_FMT_CSRATTRS = 285,
    COAP_FMT_PKCS10 = 286,
    COAP_FMT_PKIX_CERT = 287,
    COAP_FMT_SENML_XML = 310,
    COAP_FMT_SENSML_XML = 311,
    COAP_FMT_SENML_ETCH_JSON = 320,
    COAP_FMT_SENML_ETCH_CBOR = 322,
    COAP_FMT_TD_JSON = 432,
    COAP_FMT_VND_OCF_CBOR = 10000,
    COAP_FMT_OSCORE = 10001,
    COAP_FMT_JSON_DEFLATE = 11050,
    COAP_FMT_CBOR_DEFLATE = 11060,
    COAP_FMT_VND_OMA_LWM2M_TLV = 11542,
    COAP_FMT_VND_OMA_LWM2M_JSON = 11543,
    // Per RFC7252, identifiers between 65000 and 65535 are reserved
    // for experiments and forbidden for inclusion on the wire as CoAP
    // Content Format options.  Thus, it is safe for us to use 65534
    // internally to signal that no content format option was enclosed
    // in a request.
    ZCOAP_FMT_NONE = 0xfffe,
    // Per RFC7252, identifiers between 65000 and 65535 are reserved
    // for experiments and forbidden for inclusion on the wire as CoAP
    // Content Format options.  Thus, it is safe for us to use 65535
    // internally to deliniate the end of a variadiac array of options
    // as passed to set_ct_mask.
    ZCOAP_FMT_SENTINEL = 0xffff,
} coap_content_format_t;

typedef uint16_t coap_ct_t;
extern void count_ct(size_t *count, ...);
extern void extract_ct(coap_ct_t *ct, ...);

typedef uint16_t coap_msg_id_t;
#define COAP_BITS_TKL 4
#pragma pack(push, 1)
/**
 * coap_msg_t
 *
 * CoAP message frame header.
 */
typedef struct coap_msg_s {
    /**
     * tkl
     *
     * CoAP message token length.
     */
    uint8_t tkl : COAP_BITS_TKL;
    /**
     * type
     *
     * CoAP message type.
     */
    uint8_t type : 2;
    /**
     * ver
     *
     * CoAP messsage version.
     */
    uint8_t ver : 2;
    /**
     * code
     *
     * CoAP message code.
     */
    struct {
        /**
         * code_detail
         *
         * CoAP message code detail field.
         */
        coap_code_t code_detail : COAP_CODE_BITS_DETAIL;
        /**
         * code_class
         *
         * CoAP message code calss field.
         */
        coap_code_t code_class : COAP_CODE_BITS_CLASS;
    } code;
    /**
     * msg_ID
     *
     * CoAP message ID.
     */
    coap_msg_id_t msg_ID;
} coap_msg_t;
#pragma pack(pop)

typedef struct coap_client_s coap_client_t; // forward declaration
typedef struct coap_req_data_s coap_req_data_t; // forward declaration

/**
 * coap_endpoint_cmp_t
 *
 * zcoap-server client response endpoint comparison interface.
 *
 * Called by the ZCoAP server to match and sort client response endpoints.
 *
 * @param a endpoint for comparison
 * @param b endpoint for comparison
 * @return negative number if a<b, 0 if a==b, positive number if a>b
 */
#ifdef __GNUC__
typedef int __attribute__((nonnull (1, 2))) (*coap_endpoint_cmp_t)(const void * const a, const void * const b);
#else
typedef int (*coap_endpoint_cmp_t)(const void * const a, const void * const b);
#endif

/**
 * coap_discard_t
 *
 * zcoap-server message discard interface.
 *
 * Called by the ZCoAP server when processing of an incoming message is
 * complete, whether that be a completion with successfully generated response
 * or silently discarding the message.
 *
 * Typical usage is to free dynamically-allocated message data.
 *
 * @param req incoming CoAP message with request-centric implementation metadata
 */
#ifdef __GNUC__
typedef void __attribute__((nonnull (1))) (* const coap_discard_t)(coap_req_data_t * const);
#else
typedef void (*const coap_discard_t)(coap_req_data_t * const);
#endif

/**
 * coap_responder_t
 *
 * zcoap-server request responder and acker interface.
 *
 * Called for all message transmissions back to the requesting client.  These
 * may be any of stand-alone ACK, piggy-backed response and non-piggy-backed
 * response.
 *
 * @param req incoming CoAP request with implementation-specific metadata
 * @param len length of the CoAP response message to be injected into the implementation-specific transport layer
 * @param rsp buffer containing a fully-formed response for injection into the implementation-specific transport layer
 */
#ifdef __GNUC__
typedef void __attribute__((nonnull (1))) (*coap_responder_t)(coap_req_data_t * const req, const size_t len, const coap_msg_t *rsp);
#else
typedef void (*coap_responder_t)(coap_req_data_t * const req, const size_t len, const coap_msg_t* rsp);
#endif

// RFC 7651 Observables

#if INT_MAX == INT16_MAX
#define ZCOAP_WORD_ALIGN_SHIFT 1
#elif INT_MAX == INT32_MAX
#define ZCOAP_WORD_ALIGN_SHIFT 2
#elif INT_MAX == INT64_MAX
#define ZCOAP_WORD_ALIGN_SHIFT 3
#else
#error no support for INT_MAX
#endif
#define ZCOAP_BITS_PER_WORD (1 << (ZCOAP_WORD_ALIGN_SHIFT + 3))

/*
 * We use part of the 16-bit message ID space to track per-subscriber-endpoint
 * subscriptions.  The maximum number of subscriptions we can support per endpoint
 * is dependent upon the number of bits in the message ID space we designate
 * for this purpose.
 */
#define ZCOAP_SUBS_PER_ROUTE (1 << ZCOAP_SUB_ID_BITS)
#define COAP_MSG_ID_BITS 16
#if ZCOAP_SUB_ID_BITS + ZCOAP_SUB_NSTART_BITS > COAP_MSG_ID_BITS
#error SUB ID and NSTART bits must fit within 16-bit message ID field!
#endif
#if ZCOAP_SUB_ID_BITS < 3
#error ZCOAP_SUB_ID_BITS must be at least 3!
#endif
#if ZCOAP_SUB_NSTART_BITS + ZCOAP_SUB_ID_BITS < COAP_MSG_ID_BITS
#define ZCOAP_SUB_RSV_BITS (COAP_MSG_ID_BITS - ZCOAP_SUB_NSTART_BITS - ZCOAP_SUB_ID_BITS)
#endif
#define ZCOAP_SUB_NSTART ((1 << ZCOAP_SUB_NSTART_BITS) - 1)
#if ZCOAP_SUB_DROP_THRESH >= ZCOAP_SUB_NSTART
#error ZCOAP_SUB_DROP_THRESH must be strictly less than ZCOAP_SUB_NSTART
#endif

/**
 * coap_subscriber_t
 *
 * The endpoint subscriber struct.  Contains all data necessary to return
 * responses to the subscriber.  Also tracks allocation of an endpoint's
 * subscription IDs.
 */
typedef struct coap_subscriber_s {
    /**
     * deep_copy_endpoint
     *
     * Deep copy of the subscriber endpoint struct.
     */
    coap_endpoint_t deep_copy_endpoint;
    /**
     * endpoint
     *
     * Subscriber endpoint (points to deep copy).
     */
    coap_endpoint_t *endpoint;
    /**
     * context
     *
     * Endpoint context as set in original request.
     */
    int context;
    /**
     * responder
     *
     * Endpoint responder callback as set in original request.
     */
    coap_responder_t responder;
    /**
     * cmp
     *
     * Endpoint comparison function as set in the subscription map.
     */
    coap_endpoint_cmp_t cmp;
    /**
     * map
     *
     * Per-endpoint subscription ID map.  We use bits of the message ID to
     * correlate ACKs to a specific subscription for a given endpoint.  Each
     * subscription must have a bit set in the subscriber's map to hold an ID.
     * If all bits in the map are set, the map is full and no more
     * subscriptions may be allocated for the given endpoint.
     */
    unsigned map[ZCOAP_SUBS_PER_ROUTE / ZCOAP_BITS_PER_WORD];
} coap_subscriber_t;

typedef struct coap_node_s coap_node_t; // forward declaration
typedef struct coap_sub_s coap_sub_t; // forward declaration
/**
 * coap_sub_t
 *
 * Observable subscription structure.
 */
struct coap_sub_s {
    /**
     * subscriber
     *
     * Subscriber for the given subscription.
     */
    coap_subscriber_t *subscriber;
    /**
     * node
     *
     * singleton tree node that has been subscribed.
     */
    coap_node_t *node;
    /**
     * token
     *
     * Subscription token as generated by the requesting endpoint.
     */
    uint64_t token;
    /**
     * pnext
     *
     * Pointer to the next field of the previous subscription in the node's
     * singly-linked subscription list.  This allows removal of a subscription
     * from the middle of the list.
     */
    coap_sub_t **pnext;
    /**
     * next
     *
     * Nodes store subscriptions in singly-linked list.  This points to the
     * next subscription in the list.
     */
    coap_sub_t *next;
    /**
     * ct
     *
     * Content type as requested by the originating endpoint by setting accept
     * option in the originating request.
     */
    coap_ct_t ct;
    #pragma pack(push, 1)
    union {
        struct {
            union {
                /**
                 * window_right
                 *
                 * Right (most recent) side of subscription outstanding message
                 * ID window.  Outstanding messages are those for which no ACK
                 * has been received.
                 */
                coap_msg_id_t window_right : ZCOAP_SUB_NSTART_BITS;
                /**
                 * rsp_id
                 *
                 * ACK (response) message ID to check against window.
                 */
                coap_msg_id_t rsp_id : ZCOAP_SUB_NSTART_BITS;
            };
            /**
             * Per-endpoint subscription ID.  We use bits of the message ID
             * field to track multiple subscriptions for a given endpoint.
             */
            coap_msg_id_t id : ZCOAP_SUB_ID_BITS;
            #ifdef ZCOAP_SUB_RSV_BITS
            coap_msg_id_t rsv : ZCOAP_SUB_RSV_BITS;
            #endif
        };
        /**
         * msg_ID
         *
         * message ID : subscription ID
         */
        coap_msg_id_t msg_ID;
    };
    #pragma pack(pop)
    /**
     * window_left
     *
     * Left (least recent) side of subscription outstanding message
     * ID window.  Outstanding messages are those for which no ACK
     * has been received.
     */
    coap_msg_id_t window_left : ZCOAP_SUB_NSTART_BITS;
    /**
     * tkl
     *
     * Subscription token length.
     */
    uint8_t tkl : COAP_BITS_TKL;
};

/**
 * coap_obs_seq_t
 *
 * Observable nodes maintain an observation sequence number of this type that
 * is used for subscribers to differntiate published values.
 */
typedef uint32_t coap_obs_seq_t;
#define COAP_OBS_SEQ_BITS 24

/**
 * coap_sub_map_t
 *
 * Observable subscription map.  Implementations that support observables must
 * allocate this and set in the root tree node.  A single map may be used for
 * multiple trees if desired.
 */
typedef struct coap_sub_map_s {
    /**
     * n_subscribers
     *
     * The number of subscribers in the subscribers map.
     */
    size_t n_subscribers;
    /**
     * Map of subscribers sorted by endpoint.
     */
    coap_subscriber_t **subscribers; // sorted on endpoint
    /**
     * n_subscriptions
     *
     * The number of subscriptions in the subtokmap and subidmap.
     */
    size_t n_subscriptions;
    /**
     * subtokmap
     *
     * Map of subscriptions sorted by endpoint+token.
     */
    coap_sub_t **subtokmap; // sorted on endpoint+token
    /**
     * subidmap
     *
     * Map of subscriptions sorted by endpoint+id.  This implementation embeds a
     * subscription ID within the message ID field to provide
     * subscription-specific differentiation of ACKs and reset messages
     * originating from common endpoints.
     */
    coap_sub_t **subidmap; // sorted on endpoint+id
    /**
     * lock
     *
     * Implementation-specific lock structure.  The server acquires the lock
     * when reading or writing subscription map structures.
     */
    coap_lock_t lock;
    /**
     * endpoint_cmp
     *
     * Implementation-specific 'endpoint-comparison' function.  This is called by
     * the zcoap-server to compare client response routing information.  This
     * can be used to identify duplicate subscriptions, match client-to-server
     * ACKs to subscriptions and to sort subscriptions.
     */
    coap_endpoint_cmp_t endpoint_cmp;
} coap_sub_map_t;

// End RFC 7651 Observable structures

/**
 * coap_req_data_t
 *
 * Implementation-specific CoAP request data to pass to zcoap-server.
 */
struct coap_req_data_s {

    /**
     * context
     *
     * Implementation-specific, transport-layer context.  Can be anything as
     * required for a particular implementation.  In a socket-based
     * implementation, this will typically be a socket file descriptor that
     * may be written for ACK and response.
     */
    int context;

    /**
     * endpoint
     *
     * Client address information to pass back to responder and acker functions.
     * Can be anything as required by a particular implementation.
     *
     * In a socket-based implementation, this would likely be a pointer to
     * struct sockaddr_in as populated by recvfrom().  This can be passed to
     * sendto() for client responses.
     *
     * In an embedded platform, this would more typically be a pointer to a
     * data frame header from a lower layer in the communication stack.  For
     * instance, in an embedded IPv4/UDP implementation, this may be a pointer
     * to the IPv4 header.  For an IPv4/UDP responder, the IPv4 header contains
     * the information necessary to route a CoAP response back to the requesting
     * node.  The UDP header (which will immediately follow the IPv4 header)
     * contains the client's outbound port, on which it will also listen for
     * responses.
     */
    coap_endpoint_t *endpoint;

    /**
     * msg
     *
     * Pointer to a message incoming to the server.  zcoap-server handles
     * requests, ACKs and reset messages.
     */
    const coap_msg_t * const msg;

    /**
     * len
     *
     * Length of the incoming message.
     */
    size_t len;

    /**
     * discard
     *
     * Implementation-specific 'discard' function to be called when zcoap-server
     * is finished processing a message.
     *
     * An implicit contract exists with call to this function: the server will
     * only call this function once and will not access *endpoint or *msg after
     * this function is called.
     *
     * If the implementation requires no explicit action for 'discard', this
     * may be left NULL.
     */
    coap_discard_t discard;

    /**
     * Implementation-specific responder function.  For issuing any of
     * stand-alone ACK, piggy-backed response and non-piggy-backed response.
     */
    coap_responder_t responder;

    /**
     * Used by the server internally to maintain state.  Cleared on injection
     * of the request into the server.
     */
    struct {
        /**
         * Pointer to a receiving singleton node.
         */
        coap_node_t *node;
        /**
         * Set on transmission of non-piggy-backed, stand-alone ACK to suppress
         * duplicate ACK from coap_rsp.
         */
        bool acked;
        /**
         * Set from contexts where we are responding to an observation request.
         */
        bool obs;
        /**
         * Written with an observable node's observation sequence number.
         */
        coap_obs_seq_t seq;
    } state;
};

typedef struct coap_opt_s {
    uint16_t num;
    uint16_t len;
    const void *val;
} coap_opt_t;

typedef uint32_t coap_opt_num_t; // technically, it's possible with delta encoding to have an option number > UINT16_MAX
typedef struct coap_msg_opt_s {
    coap_opt_num_t num;
    uint16_t len;
    const void *val;
} coap_msg_opt_t;

/**
 * ZCOAP_METHOD_SIGNATURE
 *
 * The ZCoAP server method interface is a bit of a sprawling thing.  To
 * simplify implentation, we define the ZCAOP_METHOD_SIGNATURE macro.  All
 * method functions for a given implementation should use this.
 */
#define ZCOAP_METHOD_SIGNATURE coap_node_t * const node, coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const coap_ct_t ct, const size_t len, const void * const payload, size_t * const ctcnt, coap_ct_t * const cts

/**
 * ZCOAP_METHOD_ARGS
 *
 * Convenience macro for passing arguments to zcoap-server method handlers.
 */
#define ZCOAP_METHOD_ARGS node, req, nopts, opts, ct, len, payload, ctcnt, cts

/**
 * ZCOAP_METHOD_HEADER
 *
 * All GET/PUT/POST/DEL handlers invoked by the ZCoAP server MUST include this
 * as the first line of their function body.  Handlers must pass to this an
 * array of COAP_FMT indicators, defining supported content types for the method.
 * The array must be terminated with ZCOAP_FMT_SENTINEL.
 *
 * @param ... zero or more COAP_FMT indicators, terminated with ZCOAP_FMT_SENTINEL
 */
#define ZCOAP_METHOD_HEADER(...) \
    if (ctcnt) { \
        count_ct(ctcnt, __VA_ARGS__); \
        return; \
    } \
    if (cts) { \
        extract_ct(cts, __VA_ARGS__); \
        return; \
    } \

#ifdef __GNUC__
typedef void __attribute__((nonnull (1, 2))) (*coap_handler_t)(ZCOAP_METHOD_SIGNATURE);
typedef void __attribute__((nonnull(1))) (*coap_init_t)(const coap_node_t * const node);
typedef const char * __attribute__((nonnull(1))) (*coap_validate_t)(const coap_node_t * const node, volatile void *data);
#else
/**
 * zcoap-server GET/PUT/POST/DELETE method interface.
 *
 * @param node URI tree node
 * @param req incoming request data
 * @param nopts number of options in the passed request
 * @param opts options parsed from the request
 * @param ct content (or accept) type designator parsed from the request, or ZCOAP_FMT_NONE
 * @param len request payload length
 * @param payload payload extracted from the request
 * @param ctcnt NULL unless called from ct extractor context
 * @param cts NULL unless called from ct extractor context
 */
typedef void (*coap_handler_t)(ZCOAP_METHOD_SIGNATURE);
/**
 * zcoap-server node initializer interface.
 *
 * @param node node to initialize
 */
typedef void (*coap_init_t)(const coap_node_t * const node);
/**
 * zcoap-server node validator interface
 *
 * @param node URI tree node for validation context
 * @param data node data to validate
 * @return const error string on validation failure; NULL on validation success
 */
typedef const char* (*coap_validate_t)(const coap_node_t * const node, volatile void* data);
#endif

/**
 * coap_recruse_t
 *
 * Recursor callback interface for depth-first, stack-based tree operations.
 *
 * @param node child node for recursion
 * @param data opaque recursion data
 * @return 0 if the server should keep iterating, else an appropriate CoAP code
 */
#ifdef __GNUC__
typedef coap_code_t __attribute__((nonnull (1, 2))) (*coap_recurse_t)(coap_node_t * const node, const void *data);
#else
typedef coap_code_t (*coap_recurse_t)(coap_node_t * const node, const void* data);
#endif

/**
 * coap_gen_t
 *
 * Dynamic URI generator interface.  Based on the passed parent context,
 * the generator should populate 0 or more children.
 *
 * @param parent node under which to dynamically generate child nodes
 * @param recursor recursive callback to which dynamically-created children should be passed
 * @param recursor_data data to pass to the recursive callback function
 * @return 0 if the server should keep iterating, else an appropriate CoAP code
 */
typedef coap_code_t
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
(*coap_gen_t)(const coap_node_t * const parent, coap_recurse_t recursor, const void *recursor_data);

/**
 * coap_wildcard_t
 *
 * Dynamic wildcard generator.  Nodes may be set with a 'wildcard' function
 * matching this interface.  If the server has matched path segments to a
 * parent node, but no child nodes match, the wildcard generator will be
 * called with child name matching the next path segment in the client request.
 *
 * This is useful for creating new, named resources in the tree that do not yet
 * exist.
 *
 * @param parent node under which to dynamically generate a matching 'wildcard' node
 * @param child name of child node to dynamically create under parent for wildcard match
 * @param recursor recursive callback to which the dynamically-created wildcard node should be passed
 * @param recursor_data data to pass to the recursive callback function
 * @return 0 if the server should keep iterating, else an appropriate CoAP code
 */
typedef coap_code_t
#ifdef __GNUC__
__attribute__((nonnull (1, 2, 3)))
#endif
(*coap_wildcard_t)(const coap_node_t * const parent, const char *child, coap_recurse_t recursor, const void *recursor_data);

struct coap_node_s {
    /**
     * seq
     *
     * Observable node sequence nunmber, embedded in updates to subscribers.
     */
    coap_obs_seq_t seq : COAP_OBS_SEQ_BITS; // observation sequence number
    union {
        /**
         * nsubs
         *
         * Observable node subscriptions linked-list.
         *
         * Because this is shared with tsubs in an anonymous union which also
         * contains the root node subscription map, it is impermissible for the
         * root node to be observable.
         */
        coap_sub_t *nsubs;
        /**
         * tsubs
         *
         * Root node map of subscriptions for the tree.
         */
        coap_sub_map_t *tsubs;
    };
    /**
     * lock
     *
     * Lock to protect nodes in multithreaded environments.  The server walks
     * the tree from node to root and acquires the first non-NULL lock when
     * dispatching method handlers.  This allows for cunstruction of trees with
     * sparse population of locks.  For instance, perhaps all nodes at and below
     * /telementry should share a single lock.  If so, a single lock can be
     * added to /telemetry and this will provide protection for it and all of
     * its children.  The simplest implementation places a single lock at the
     * tree root node.
     */
    coap_lock_t *lock;
    /**
     * name
     *
     * Node path segment name
     */
    const char *name;
    /**
     * data
     *
     * Opaque node data pointer.
     */
    volatile void *data;
    /**
     * fmt
     *
     * Node printf format for plain text responses.  If NULL, a default is used
     * for responses.
     */
    const char *fmt;
    /**
     * parent
     *
     * Parent node pointer, populated by the server at runtime.  May be used by
     * method handlers to locate parents or root.
     */
    const coap_node_t *parent;
    /**
     * children
     *
     * NULL-terminated array of child nodes, or NULL for leaf nodes.
     */
    coap_node_t **children;
    /**
     * gen
     *
     * Child-node generator function, or NULL.
     */
    coap_gen_t gen;
    /**
     * wildcard
     *
     * Wildcard child-node generator for generating a matching wildcard child
     * node when no other children match a request's path segment.
     */
    coap_wildcard_t wildcard;
    /**
     * GET
     *
     * GET method pointer, or NULL for nodes that do not support GET.
     */
    coap_handler_t GET;
    /**
     * PUT
     *
     * PUT method pointer, or NULL for nodes that do not support PUT.
     */
    coap_handler_t PUT;
    /**
     * POST
     *
     * POST method pointer, or NULL for nodes that do not support POST.
     */
    coap_handler_t POST;
    /**
     * DEL
     *
     * DELETE method pointer, or NULL for nodes that do not support DELETE.
     */
    coap_handler_t DEL;
    /**
     * init
     *
     * Node initialization fucntion called by the server at tree init.
     */
    coap_init_t init;
    /**
     * validate
     *
     * Node data validator called at init and from zcoap-server's PUT/POST
     * utility methods.
     */
    coap_validate_t validate;
    /**
     * metadata
     *
     * Node metadata.  Can be anything as necessary for a node's handler's to
     * understand their context.
     */
    const void *metadata;
    /**
     * hidden
     *
     * If true, do not advertise in .well-known/core
     */
    bool hidden : 1;
    /**
     * singleton
     *
     * If true, this node is a singleton in the tree and can support
     * subscriptions.  This is set automatically by zcoap-server.
     */
    bool singleton : 1;
    /**
     * observable
     *
     * If true, allow observable subscriptions.
     */
    bool observable : 1;
    /**
     * instance
     *
     * State flag to ensure we only increment seq once per update of a given
     * observable.
     */
    bool instance : 1;
};

// The following define our format for binary booleans on the wire.  We have:
// 1) width, 2) encoding and implicitly 3) endianness.  Endianness is inherent
// by virtue of our chosen field width being only one byte long.  We can cast
// to other binary line types, which will generally produce values with sensible
// truthiness.  That only occurs, however, with a client content format request
// mismatch.
typedef uint8_t zcoap_bool_t;
#define ZCOAP_TRUE_STR "true"
#define ZCOAP_FALSE_STR "false"

extern coap_code_t coap_get_content_type(coap_req_data_t* req, size_t nopts, const coap_msg_opt_t opts[], coap_ct_t* ct);
extern coap_code_t coap_get_size1(coap_req_data_t* req, size_t nopts, const coap_msg_opt_t opts[], bool* found, uint32_t* size1);
extern coap_code_t coap_count_query_opts(coap_req_data_t* req, size_t nopts, const coap_msg_opt_t opts[], size_t* nqueryopts);
extern coap_code_t coap_get_query_opts(coap_req_data_t* req, size_t nopts, const coap_msg_opt_t opts[], size_t nqueryopts, coap_msg_opt_t* queryopts);
extern coap_code_t coap_get_payload(coap_req_data_t* req, size_t* len, const void** payload);
extern void coap_publish(coap_node_t *node); // publish an update to observers of the passed node
extern void coap_publish_all(coap_sub_map_t *map); // publish an update to all observers
extern void coap_cancel(coap_node_t *node); // cancel all subscriptions for the passed node
extern void coap_cancel_all(coap_sub_map_t *map); // cancel all observer subscriptions
extern void coap_garbage_collect(coap_sub_map_t *map); // garbage collect observer subscriptions

extern void coap_ack(coap_req_data_t* req);
extern void coap_rsp(coap_req_data_t* req, coap_code_t code, size_t nopts, const coap_opt_t opts[], size_t pl_len, const void* payload);
extern void coap_content_rsp(coap_req_data_t* req, coap_code_t code, coap_ct_t ct, size_t pl_len, const void* payload);
extern void coap_status_rsp(coap_req_data_t* req, coap_code_t code);
extern void coap_detail_rsp(coap_req_data_t* req, coap_code_t code, const char* detail);
extern void coap_printf(coap_req_data_t* req, const char* fmt, ...);

extern void coap_return_bool(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], bool val);
extern void coap_return_u16(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], const char *fmt, uint16_t val);
extern void coap_return_u32(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], const char *fmt, uint32_t val);
extern void coap_return_u64(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], const char *fmt, uint64_t val);
extern void coap_return_i16(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], const char *fmt, int16_t val);
extern void coap_return_i32(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], const char *fmt, int32_t val);
extern void coap_return_i64(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], const char *fmt, int64_t val);
extern void coap_return_float(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], const char *fmt, float val);
extern void coap_return_double(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], const char *fmt, ZCOAP_DOUBLE val);

extern void coap_get_string(ZCOAP_METHOD_SIGNATURE);
extern void coap_get_bool(ZCOAP_METHOD_SIGNATURE);
extern void coap_get_u16(ZCOAP_METHOD_SIGNATURE);
extern void coap_get_u32(ZCOAP_METHOD_SIGNATURE);
extern void coap_get_u64(ZCOAP_METHOD_SIGNATURE);
extern void coap_get_i16(ZCOAP_METHOD_SIGNATURE);
extern void coap_get_i32(ZCOAP_METHOD_SIGNATURE);
extern void coap_get_i64(ZCOAP_METHOD_SIGNATURE);
extern void coap_get_float(ZCOAP_METHOD_SIGNATURE);
extern void coap_get_double(ZCOAP_METHOD_SIGNATURE);

extern coap_code_t coap_parse_bool(const void *ascii, size_t len, bool *out);
extern coap_code_t coap_parse_uint(const void *ascii, size_t len, unsigned *out);
extern coap_code_t coap_parse_ulong(const void *ascii, size_t len, unsigned long *out);
extern coap_code_t coap_parse_ullong(const void *ascii, size_t len, unsigned long long *out);
extern coap_code_t coap_parse_int(const void *ascii, size_t len, int *out);
extern coap_code_t coap_parse_long(const void *ascii, size_t len, long *out);
extern coap_code_t coap_parse_llong(const void *ascii, size_t len, long long *out);
extern coap_code_t coap_parse_float(const void *ascii, size_t len, float *out);
extern coap_code_t coap_parse_double(const void *ascii, size_t len, ZCOAP_DOUBLE *out);

extern coap_code_t coap_parse_req_bool(coap_ct_t ct, size_t len, const void *payload, bool *out);
extern coap_code_t coap_parse_req_u16(coap_ct_t ct, size_t len, const void *payload, uint16_t *out);
extern coap_code_t coap_parse_req_u32(coap_ct_t ct, size_t len, const void *payload, uint32_t *out);
extern coap_code_t coap_parse_req_u64(coap_ct_t ct, size_t len, const void *payload, uint64_t *out);
extern coap_code_t coap_parse_req_i16(coap_ct_t ct, size_t len, const void *payload, int16_t *out);
extern coap_code_t coap_parse_req_i32(coap_ct_t ct, size_t len, const void *payload, int32_t *out);
extern coap_code_t coap_parse_req_i64(coap_ct_t ct, size_t len, const void *payload, int64_t *out);
extern coap_code_t coap_parse_req_float(coap_ct_t ct, size_t len, const void *payload, float *out);
extern coap_code_t coap_parse_req_double(coap_ct_t ct, size_t len, const void *payload, ZCOAP_DOUBLE *out);

extern void coap_put_bool(ZCOAP_METHOD_SIGNATURE);
extern void coap_put_u16(ZCOAP_METHOD_SIGNATURE);
extern void coap_put_u32(ZCOAP_METHOD_SIGNATURE);
extern void coap_put_u64(ZCOAP_METHOD_SIGNATURE);
extern void coap_put_i16(ZCOAP_METHOD_SIGNATURE);
extern void coap_put_i32(ZCOAP_METHOD_SIGNATURE);
extern void coap_put_i64(ZCOAP_METHOD_SIGNATURE);
extern void coap_put_float(ZCOAP_METHOD_SIGNATURE);
extern void coap_put_double(ZCOAP_METHOD_SIGNATURE);

#if INT_MAX == INT16_MAX
#define coap_return_uint coap_return_u16
#define coap_return_int coap_return_i16
#define coap_get_uint coap_get_u16
#define coap_get_int coap_get_i16
#define coap_parse_req_uint coap_parse_req_u16
#define coap_parse_req_int coap_parse_req_i16
#define coap_put_uint coap_put_u16
#define coap_put_int coap_put_i16
#elif INT_MAX == INT32_MAX
#define coap_return_uint coap_return_u32
#define coap_return_int coap_return_i32
#define coap_get_uint coap_get_u32
#define coap_get_int coap_get_i32
#define coap_parse_req_uint coap_parse_req_u32
#define coap_parse_req_int coap_parse_req_i32
#define coap_put_uint coap_put_u32
#define coap_put_int coap_put_i32
#elif INT_MAX == INT64_MAX
#define coap_return_uint coap_return_u64
#define coap_return_int coap_return_i64
#define coap_get_uint coap_get_u64
#define coap_get_int coap_get_i64
#define coap_parse_req_uint coap_parse_req_u64
#define coap_parse_req_int coap_parse_req_i64
#define coap_put_uint coap_put_u64
#define coap_put_int coap_put_i64
#else
#error no support for INT_MAX
#endif

extern void coap_init(coap_node_t root); // <- init must be called against any URI tree before it is passed to the server!
extern void coap_rx(coap_req_data_t* req, coap_node_t root); // <- server entry point!

extern coap_node_t wellknown_uri;

#endif /* ZCOAP_SERVER_H */
