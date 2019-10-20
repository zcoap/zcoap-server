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
#include "config.h"

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
    COAP_REQ_METHOD_DELETE = 4,
};

enum {
    COAP_SUCCESS_DELETE = 2,
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
    #ifdef ZCOAP_EXTENSIONS
    // Client error code 409, Conflict
    //
    // This is a non-RFC-7252 error code taken from HTTP.  ZCoAP server can
    // use this code to reflect conditions to clients whereby requested actions
    // cannot be completed due to preexisting state or subsequent requests that
    // conflict with the client request for which the error response is
    // returned.
    COAP_CLIENT_ERR_CONFLICT = 9,
    #endif /* ZCOAP_EXTENSIONS */
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
#define COAP_CODE_TO_CLASS(_code) (((_code) >> COAP_CODE_BITS_CLASS) & COAP_CODE_MASK_CLASS)

enum {
    COAP_OPT_IF_MATCH = 1,
    COAP_OPT_URI_HOST = 3,
    COAP_OPT_ETAG = 4,
    COAP_OPT_IF_NONE_MATCH = 5,
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
    COAP_FMT_TEXT = 0,
    COAP_FMT_LINK = 40,
    COAP_FMT_XML = 41,
    COAP_FMT_STREAM = 42,
    COAP_FMT_EXI = 47,
    COAP_FMT_JSON = 50,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_AUTO = 72,
    ZCOAP_FMT_BOOL,
    ZCOAP_FMT_U16,
    ZCOAP_FMT_U32,
    ZCOAP_FMT_U64,
    ZCOAP_FMT_I16,
    ZCOAP_FMT_I32,
    ZCOAP_FMT_I64,
    ZCOAP_FMT_FLOAT,
    ZCOAP_FMT_DOUBLE,
    #endif /* ZCOAP_EXTENSIONS */
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
typedef union ct_mask_s {
    struct {
        uint32_t ct_text : 1;
        uint32_t ct_link : 1;
        uint32_t ct_xml : 1;
        uint32_t ct_ostream : 1;
        uint32_t ct_exi : 1;
        uint32_t ct_json : 1;
        #ifdef ZCOAP_EXTENSIONS
        uint32_t ct_bool : 1;
        uint32_t ct_u16 : 1;
        uint32_t ct_u32 : 1;
        uint32_t ct_u64 : 1;
        uint32_t ct_i16 : 1;
        uint32_t ct_i32 : 1;
        uint32_t ct_i64 : 1;
        uint32_t ct_float : 1;
        uint32_t ct_double : 1;
        uint32_t rsv : 1;
        #else
        uint32_t rsv : 10;
        #endif
        uint32_t literal_set : 1;
    };
    coap_ct_t ct_literal;
} ct_mask_t;

extern void set_ct_mask(ct_mask_t * const mask, ...);
extern void set_ct_mask_literal(ct_mask_t * const mask, coap_ct_t ct);

/**
 * ZCOAP_METHOD_SIGNATURE
 *
 * The ZCoAP CoAP server method interface is a bit of a sprawling thing.  To
 * simplify implentation, we define the ZCAOP_METHOD_SIGNATURE macro.  All
 * method functions for a given implementation should use this.
 */
#define ZCOAP_METHOD_SIGNATURE const coap_node_t * const node, coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const coap_ct_t ct, const size_t len, const void * const payload, ct_mask_t * const ctmask

/**
 * ZCOAP_METHOD_HEADER
 *
 * All GET/PUT/POST/DELETE handlers invoked by the ZCoAP CoAP server MUST include
 * this as the first line of the function body.  Handlers must pass to this an
 * array of COAP_FMT indicators, defining supported content types for the method.
 * The array must be terminated with ZCOAP_FMT_SENTINEL.
 *
 * @param ... zero or more COAP_FMT indicators, terminated with ZCOAP_FMT_SENTINEL
 */
#define ZCOAP_METHOD_HEADER(...) if (ctmask) { set_ct_mask(ctmask, __VA_ARGS__); return; }


typedef struct coap_msg_s {
    uint8_t tkl : 4;
    uint8_t type : 2;
    uint8_t ver : 2;
    struct {
        coap_code_t code_detail : COAP_CODE_BITS_DETAIL;
        coap_code_t code_class : COAP_CODE_BITS_CLASS;
#ifdef __GNUC__
    } __attribute__((packed)) code;
#else
} code; //NEED a PRAGMA Pack for this - pack
#endif

uint16_t msg_ID;

#ifdef __GNUC__
	} __attribute__((packed)) coap_msg_t;
#else
} coap_msg_t;
#endif

typedef struct coap_req_data_s coap_req_data_t; // forward declaration

/**
 * coap_discard_t
 *
 * zcoap-server message discard interface.
 *
 * Called by the ZCoAP CoAP server when processing of an incoming message is
 * complete, whether that be a completion with successfully generated response
 * or silently discarding the message.
 *
 * Typical usage is to free dynamically-allocated message data.
 *
 * @param req incoming CoAP message with request-centric implementation metadata
 */

#ifdef __GNUC__
typedef void __attribute__((nonnull (1))) (* const coap_discard_t)(coap_req_data_t * const req);
#else
typedef void (*const coap_discard_t)(coap_req_data_t* const req);
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
typedef void __attribute__((nonnull (1))) (* const coap_responder_t)(coap_req_data_t * const req, const size_t len, const coap_msg_t *rsp);
#else
typedef void (*const coap_responder_t)(coap_req_data_t* const req, const size_t len, const coap_msg_t* rsp);
#endif

/**
 */
struct coap_req_data_s {

    /**
     * Implementation-specific, transport-layer context.  Can be anything as
     * required for a particular implementation.  In a socket-based
     * implementation, this will typically be a socket file descriptor that
     * may be written for ACK and response.
     */
    const int context;

    /**
     * route
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
    const void * const route;

    /**
     * msg
     *
     * Pointer to a message incoming to the server.  Presumably this will be a
     * request.
     */
    const coap_msg_t * const msg;

    /**
     * len
     *
     * Length of the incoming message.
     */
    const size_t len;

    /*
     * discard
     *
     * Implementation-specific 'discard' function to be called when a message
     * is to be ignored by the server.  This will be the case, for instance,
     * if the incoming message is not a request.
     *
     * An implicit contract exists with call to this function: the server will
     * only call this function once and will not access *header or *msg after
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
         * Set on transmission of non-piggy-backed, stand-alone ACK to suppress
         * duplicate ACK from coap_rsp.
         */
        bool acked;
    } state;
};

typedef struct coap_opt_s {
    uint16_t num;
    uint16_t len;
    const void *val;
} coap_opt_t;

typedef struct coap_msg_opt_s {
    uint32_t num;
    uint16_t len;
    const void *val;
} coap_msg_opt_t;

typedef struct coap_node_s coap_node_t; // forward declaration

#ifdef __GNUC__
typedef void __attribute__((nonnull (1, 2))) (*coap_handler_t)(ZCOAP_METHOD_SIGNATURE);
typedef void __attribute__((nonnull(1))) (*coap_init_t)(const coap_node_t * const node);
typedef const char * __attribute__((nonnull(1))) (*coap_validate_t)(volatile void *data);
#else
typedef void (*coap_handler_t)(ZCOAP_METHOD_SIGNATURE);
typedef void (*coap_init_t)(const coap_node_t* const node);
typedef const char* (*coap_validate_t)(volatile void* data); 
#endif

/**
 * coap_recruse_t
 *
 * Recursor callback interface for depth-first, stack-based tree operations.
 */
#ifdef __GNUC__
typedef coap_code_t __attribute__((nonnull (1, 2))) (*coap_recurse_t)(const coap_node_t * const node, const void *data);
#else
typedef coap_code_t (*coap_recurse_t)(const coap_node_t* const node, const void* data);
#endif

/**
 * coap_gen_t
 *
 * Dynamic URI generator interface.  Based on the passed parent context,
 * the generator should populate 0 or more children.  Children must be allocated
 * with the caller-passed allocator.  The caller then becomes responsible for
 * freeing children with a symetric free function.
 *
 * @param parent node under which to dynamically generate child nodes
 * @param recursor recursive callback to which dynamically-created children should be passed
 * @param recursor_data data to pass to the recursive callback function
 * @return 0 on success, an appropriate CoAP error code on failure
 */
#ifdef __GNUC__
typedef coap_code_t __attribute__((nonnull (1, 2))) (*coap_gen_t)(const coap_node_t * const parent, coap_recurse_t recursor, const void *recursor_data);
#else
typedef coap_code_t (*coap_gen_t)(const coap_node_t* const parent, coap_recurse_t recursor, const void* recursor_data);
#endif

struct coap_node_s {
    const char *name; // node path segment
    volatile void *data; // node data pointer
    const char *fmt; // print format for plain text responses; if NULL, zcoap.c utility GET functions use default format
    const coap_node_t *parent; // pointer to parent node, or NULL for the root node; set by zcoap.c
    const coap_node_t **children; // must be NULL or point to a NULL-terminated array of child noes
    coap_gen_t gen; // must be NULL or point to a child-node generator
    coap_handler_t GET; // GET method pointer; must be NULL or point to a valid zcoap GET method handler
    coap_handler_t PUT; // PUT method pointer; must be NULL or point to a valid zcoap GET method handler
    coap_handler_t POST; // POST method pointer; must be NULL or point to a valid zcoap GET method handler
    coap_handler_t DELETE; // DELETE method pointer; must be NULL or point to a valid zcoap GET method handler
    coap_init_t init; // init function to call against the node at system init; called by zcoap.c at init if non-null
    coap_validate_t validate; // utility validator for init and PUT/POST; called by zcoap.c PUT/POST utility methods if non-null
    const void *metadata; // node metadata; can be anything as necessary for a node's handlers to understand their context
    bool wildcard : 1; // if true, all children match to this parent if no explicit child-node match is found
    bool hidden : 1; // if true, do not advertise in .well-known/core
};

// The following define our format for binary booleans on the wire.  We have:
// 1) width, 2) encoding and implicitly 3) endianness.  Endianness is inherent
// by virtue of our chosen field width being only one byte long.  We can cast
// to other binary line types, which will generally produce values with sensible
// truthiness.  That only occurs, however, with a client content format request
// mismatch.
typedef uint8_t zcoap_bool_t;
#define ZCOAP_TRUE ((zcoap_bool_t)1)
#define ZCOAP_FALSE ((zcoap_bool_t)0)
#define ZCOAP_TRUE_STR "true"
#define ZCOAP_FALSE_STR "false"
#define TO_ZCOAP_BOOL(_b) ((_b) ? ZCOAP_TRUE : ZCOAP_FALSE)

#ifdef __GNUC__
extern coap_code_t __attribute__((nonnull (1, 4))) coap_get_content_type(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], coap_ct_t *ct);
extern coap_code_t __attribute__((nonnull (4, 5))) coap_get_size1(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], bool *found, uint32_t *size1);
extern coap_code_t __attribute__((nonnull (1, 4))) coap_count_query_opts(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], size_t *nqueryopts);
extern coap_code_t __attribute__((nonnull (1, 5))) coap_get_query_opts(coap_req_data_t *req, size_t nopts, const coap_msg_opt_t opts[], size_t nqueryopts, coap_msg_opt_t *queryopts);
extern coap_code_t __attribute__((nonnull (1))) coap_get_payload(coap_req_data_t *req, size_t *len, const void **payload);

extern void __attribute__((nonnull (1))) coap_ack(coap_req_data_t *req);
extern void __attribute__((nonnull (1))) coap_rsp(coap_req_data_t *req, coap_code_t code, size_t nopts, const coap_opt_t opts[], size_t pl_len, const void *payload);
extern void __attribute__((nonnull (1))) coap_content_rsp(coap_req_data_t *req, coap_code_t code, coap_ct_t ct, size_t pl_len, const void *payload);
extern void __attribute__((nonnull (1))) coap_status_rsp(coap_req_data_t *req, coap_code_t code);
extern void __attribute__((nonnull (1))) coap_detail_rsp(coap_req_data_t *req, coap_code_t code, const char *detail);

#else

extern coap_code_t coap_get_content_type(coap_req_data_t* req, size_t nopts, const coap_msg_opt_t opts[], coap_ct_t* ct);
extern coap_code_t coap_get_size1(coap_req_data_t* req, size_t nopts, const coap_msg_opt_t opts[], bool* found, uint32_t* size1);
extern coap_code_t coap_count_query_opts(coap_req_data_t* req, size_t nopts, const coap_msg_opt_t opts[], size_t* nqueryopts);
extern coap_code_t coap_get_query_opts(coap_req_data_t* req, size_t nopts, const coap_msg_opt_t opts[], size_t nqueryopts, coap_msg_opt_t* queryopts);
extern coap_code_t coap_get_payload(coap_req_data_t* req, size_t* len, const void** payload);

extern void coap_ack(coap_req_data_t* req);
extern void coap_rsp(coap_req_data_t* req, coap_code_t code, size_t nopts, const coap_opt_t opts[], size_t pl_len, const void* payload);
extern void coap_content_rsp(coap_req_data_t* req, coap_code_t code, coap_ct_t ct, size_t pl_len, const void* payload);
extern void coap_status_rsp(coap_req_data_t* req, coap_code_t code);
extern void coap_detail_rsp(coap_req_data_t* req, coap_code_t code, const char* detail);

#endif

#ifdef __GNUC__
extern void coap_printf(coap_req_data_t *req, const char *fmt, ...) __attribute__((format (printf, 2, 3)));
#else
extern void coap_printf(coap_req_data_t* req, const char* fmt, ...);
#endif

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

extern int coap_parse_bool(const void *ascii, size_t len, bool *out);
extern int coap_parse_uint(const void *ascii, size_t len, unsigned *out);
extern int coap_parse_ulong(const void *ascii, size_t len, unsigned long *out);
extern int coap_parse_ullong(const void *ascii, size_t len, unsigned long long *out);
extern int coap_parse_int(const void *ascii, size_t len, int *out);
extern int coap_parse_long(const void *ascii, size_t len, long *out);
extern int coap_parse_llong(const void *ascii, size_t len, long long *out);
extern int coap_parse_float(const void *ascii, size_t len, float *out);
extern int coap_parse_double(const void *ascii, size_t len, ZCOAP_DOUBLE *out);

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
#define ZCOAP_FMT_INT ZCOAP_FMT_I16
#define ZCOAP_FMT_UINT ZCOAP_FMT_U16
#define coap_return_uint coap_return_u16
#define coap_return_int coap_return_i16
#define coap_get_uint coap_get_u16
#define coap_get_int coap_get_i16
#define coap_parse_req_uint coap_parse_req_u16
#define coap_parse_req_int coap_parse_req_i16
#define coap_put_uint coap_put_u16
#define coap_put_int coap_put_i16
#elif INT_MAX == INT32_MAX
#define ZCOAP_FMT_INT ZCOAP_FMT_I32
#define ZCOAP_FMT_UINT ZCOAP_FMT_U32
#define coap_return_uint coap_return_u32
#define coap_return_int coap_return_i32
#define coap_get_uint coap_get_u32
#define coap_get_int coap_get_i32
#define coap_parse_req_uint coap_parse_req_u32
#define coap_parse_req_int coap_parse_req_i32
#define coap_put_uint coap_put_u32
#define coap_put_int coap_put_i32
#elif INT_MAX == INT64_MAX
#define ZCOAP_FMT_INT ZCOAP_FMT_I64
#define ZCOAP_FMT_UINT ZCOAP_FMT_U64
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

extern void coap_init(const coap_node_t *root); // <- init must be called against any URI trees before it is passed to the server!

#ifdef __GNUC__
extern void __attribute__((nonnull (1, 2))) coap_rx(coap_req_data_t *req, const coap_node_t *root); // <- server entry point!
#else
extern void coap_rx(coap_req_data_t* req, const coap_node_t* root); // <- server entry point!
#endif
extern const coap_node_t wellknown_uri;

#endif	/* ZCOAP_SERVER_H */
