/*
 * File:   zcoap-server.h
 * Author: Michael Sandstedt
 *
 * Created on March 31, 2018, 1:24 PM
 */

#ifndef ZCOAP_SERVER_H
#define ZCOAP_SERVER_H

#include <stdbool.h>
#include <stdarg.h>
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
    ZFMT_AUTO = 72,
    ZFMT_BOOL,
    ZFMT_U16,
    ZFMT_U32,
    ZFMT_U64,
    ZFMT_I16,
    ZFMT_I32,
    ZFMT_I64,
    ZFMT_FLOAT,
    ZFMT_DOUBLE,
    #endif /* ZCOAP_eXTENSIONS */
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
    ZCOAP_FMT_SENTINEL = 0xffff
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

extern void set_ct_mask(ct_mask_t *mask, ...);
extern void set_ct_mask_literal(ct_mask_t *mask, coap_ct_t ct);

/**
 * ZCOAP_METHOD_SIGNATURE
 *
 * The ZCoAP CoAP server method interface is a bit of a sprawling thing.  To
 * simplify implentation, we define the ZCAOP_METHOD_SIGNATURE macro.  All
 * method functions for a given implementation should use this.
 */
#define ZCOAP_METHOD_SIGNATURE const coap_node_t *node, coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], coap_ct_t ct, size_t len, void *payload, ct_mask_t *ctmask

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
    } __attribute__((packed)) code;
    uint16_t msg_ID;
} __attribute__((packed)) coap_msg_t;

typedef struct coap_req_data_s coap_req_data_t; // forward declaration

/**
 * coap_discard_t
 *
 * Implementation CoAP message discard interface.
 *
 * Called by the ZCoAP CoAP server when processing of an incoming message is
 * complete, whether that be a completion with successfully generated response
 * or a silent discard of the message.
 *
 * Typical usage is to free dynamically-allocated message data.
 *
 * @param req incoming CoAP message with request-centric implementation metadata
 */
typedef void __attribute__((nonnull (1))) (*coap_discard_t)(coap_req_data_t *req);
/**
 * coap_acker_t
 *
 * Implementation confirmable CoAP message ACK dispatch interface.
 *
 * Request handler methods may call coap_ack for stand-alone immediate ACK when
 * non-piggy-packed response behavior is preferred over the ZCoAP CoAP server's
 * default piggy-backed ACK / response behavior.
 *
 * This is appropriate for long-running operations when immediate ACK is
 * preferred and response will be generated sometime later.
 *
 * When request handler methods call coap_ack, the ZCoAP CoAP server uses the
 * implementation's acker function to dispatch ACK into the implementation's
 * transport layer.  On dispatch, the ZCoAP CoAP server will set CONFIRMABLE
 * messages to type NON-CONFIRMABLE.  This will prevent duplicate ACK when
 * requests are eventually passed to coap_rsp.
 *
 * @param req incoming CoAP request with implementation-specific metadata
 */
typedef void __attribute__((nonnull (1))) (*coap_acker_t)(coap_req_data_t *req, coap_msg_t *ack);
typedef void __attribute__((nonnull (1))) (*coap_responder_t)(coap_req_data_t *req, size_t len, coap_msg_t *rsp);

/**
 */
struct coap_req_data_s {
    /**
     * header
     *
     * Buffer to pass back to responder and acker functions.  Can be anything
     * as required by a particular implementation.  But typically this will be
     * a pointer to a data frame header from a lower layer in the communication
     * stack.  For instance, in an IPv4/UDP implementation, this may be a
     * pointer to the IPv4 header.  For an IPv4/UDP responder, the IPv4 header
     * contains the information necessary to route a CoAP response back to the
     * requesting agent.
     */
    void *header;
    /**
     * context
     *
     * Implementation-specific context data to pass back to responder and acker
     * functions.  For an IPv4/UDP posix responder, this could for instance be
     * a file descriptor for a socket bound to the client/server connection
     * tuple.  In such an environment, the responder may simply write the
     * response to the file descriptor.
     */
    int context;
    /**
     * msg
     *
     * Pointer to a message incoming to the server.  Presumably this will be a
     * request.
     */
    coap_msg_t *msg;
    /**
     * len
     *
     * Length of the incoming message.
     */
    size_t len;
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
    coap_discard_t *discard;
    /*
     * acker
     *
     * Implementation-specific 'ack' function for stand-alone ACK with
     * non-piggy-backed responses.  As intent for this is stand-alone ACK
     * before non-piggy-backed response, the server will continue to access
     * *header and *msg after this is called.
     *
     * Need for stand-alone ACK is dependent on the URI.  Method handlers may
     * therefore choose to execute this or not.
     *
     * May be left NULL if stand-alone ACK and non-piggy-backed responses are
     * not needed.
     */
    coap_acker_t acker;
    /**
     * Implementation-specific responder function.  For issuing both
     * piggy-backed and non-piggy-backed responses.  An implicit contract
     * exists with call to this function: the server must only call this
     * function once and must not access *header or *msg after this function
     * is called.
     */
    coap_responder_t responder;
};

typedef struct coap_opt_s {
    uint16_t num;
    uint16_t len;
    const void *val;
} coap_opt_t;

typedef struct coap_msg_opt_s {
    uint32_t num;
    uint16_t len;
    void *val;
} coap_msg_opt_t;

typedef unsigned coap_meta_t;
typedef struct coap_node_s coap_node_t; // forward declaration
typedef void __attribute__((nonnull (1, 2))) (*coap_handler_t)(ZCOAP_METHOD_SIGNATURE);
typedef void __attribute__((nonnull(1))) (*coap_init_t)(const coap_node_t *node);
typedef const char * __attribute__((nonnull(1))) (*coap_validate_t)(volatile void *data);

/*
 * coap_gen_t: meta-object generator function interface
 *
 * The caller must allocate memory for iterator, object and metadata, and must
 * initialize iterator to 0.  The generator function should return 0 and write
 * dynamically generated data to object and metadata so long as there are more
 * objects available.  Each object is a dynamically generated node in our tree.
 * For each object, the generator also writes the metadata output variable with
 * with the information necessary to call the object methods in an instance-
 * specific manner.
 *
 * Once there are no more dynamic objects, the generator should return non-zero.
 */
typedef int (*coap_gen_t)(coap_meta_t *iterator, coap_node_t *object);

struct coap_node_s {
    const char *name; // node path segment
    volatile void *data; // node data pointer
    const char *fmt; // print format for plain text responses; if NULL, zcoap.c utility GET functions use default format
    const coap_node_t *parent; // pointer to parent node, or NULL for the root node; set by zcoap.c
    const coap_node_t **children; // must be NULL or point to a NULL-terminated array of child noes
    const coap_gen_t *gens; // must be NULL or point to a NULL-terminated array of child-node generators
    coap_handler_t GET;
    coap_handler_t PUT;
    coap_handler_t POST;
    coap_handler_t DELETE;
    coap_init_t init; // init function to call against the node at system init; called by zcoap.c at init if non-null
    coap_validate_t validate; // utility validator for init and PUT/POST; called by zcoap.c PUT/POST utility methods if non-null
    coap_meta_t metadata; // node metadata
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

extern coap_code_t __attribute__((nonnull (1, 4))) coap_get_content_type(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], coap_ct_t *ct);
extern coap_code_t __attribute__((nonnull (4, 5))) coap_get_size1(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], bool *found, uint32_t *size1);
extern coap_code_t __attribute__((nonnull (1, 4))) coap_count_query_opts(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], size_t *nqueryopts);
extern coap_code_t __attribute__((nonnull (1, 5))) coap_get_query_opts(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], size_t nqueryopts, coap_msg_opt_t queryopts[]);
extern coap_code_t __attribute__((nonnull (1))) coap_get_payload(coap_req_data_t *req, size_t *len, void **payload);

extern void __attribute__((nonnull (1))) coap_ack(coap_req_data_t *req);
extern void __attribute__((nonnull (1))) coap_rsp(coap_req_data_t *req, coap_code_t code, size_t nopts, const coap_opt_t opts[], size_t pl_len, void *payload);
extern void __attribute__((nonnull (1))) coap_content_rsp(coap_req_data_t *req, coap_code_t code, coap_ct_t ct, size_t pl_len, void *payload);
extern void __attribute__((nonnull (1))) coap_status_rsp(coap_req_data_t *req, coap_code_t code);
extern void __attribute__((nonnull (1))) coap_detail_rsp(coap_req_data_t *req, coap_code_t code, const char *detail);

extern void coap_printf(coap_req_data_t *req, const char *fmt, ...) __attribute__((format (printf, 2, 3)));
extern void coap_return_bool(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], bool val);
extern void coap_return_u16(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const char *fmt, uint16_t val);
extern void coap_return_u32(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const char *fmt, uint32_t val);
extern void coap_return_u64(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const char *fmt, uint64_t val);
extern void coap_return_i16(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const char *fmt, int16_t val);
extern void coap_return_i32(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const char *fmt, int32_t val);
extern void coap_return_i64(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const char *fmt, int64_t val);
extern void coap_return_float(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const char *fmt, float val);
extern void coap_return_double(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const char *fmt, ZCOAP_DOUBLE val);

extern void coap_get_bool(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_get_u16(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_get_u32(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_get_u64(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_get_i16(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_get_i32(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_get_i64(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_get_float(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_get_double(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);

extern int coap_parse_bool(void *ascii, size_t len, bool *out, size_t *size1);
extern int coap_parse_u16(void *ascii, size_t len, uint16_t *out, size_t *size1);
extern int coap_parse_u32(void *ascii, size_t len, uint32_t *out, size_t *size1);
extern int coap_parse_u64(void *ascii, size_t len, uint64_t *out, size_t *size1);
extern int coap_parse_i16(void *ascii, size_t len, int16_t *out, size_t *size1);
extern int coap_parse_i32(void *ascii, size_t len, int32_t *out, size_t *size1);
extern int coap_parse_i64(void *ascii, size_t len, int64_t *out, size_t *size1);
extern int coap_parse_float(void *ascii, size_t len, float *out, size_t *size1);
extern int coap_parse_double(void *ascii, size_t len, ZCOAP_DOUBLE *out, size_t *size1);

extern coap_code_t coap_parse_req_bool(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], bool *out);
extern coap_code_t coap_parse_req_u16(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], uint16_t *out);
extern coap_code_t coap_parse_req_u32(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], uint32_t *out);
extern coap_code_t coap_parse_req_u64(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], uint64_t *out);
extern coap_code_t coap_parse_req_i16(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], int16_t *out);
extern coap_code_t coap_parse_req_i32(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], int32_t *out);
extern coap_code_t coap_parse_req_i64(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], int64_t *out);
extern coap_code_t coap_parse_req_float(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], float *out);
extern coap_code_t coap_parse_req_double(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], ZCOAP_DOUBLE *out);

extern void coap_put_bool(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_put_u16(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_put_u32(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_put_u64(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_put_i16(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_put_i32(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_put_i64(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_put_float(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);
extern void coap_put_double(coap_req_data_t *req, size_t nopts, coap_msg_opt_t opts[], const coap_node_t *node, ct_mask_t *ct_mask);

extern void coap_init(coap_node_t *root); // <- init must be called against any URI trees before it is passed to the server!
extern void __attribute__((nonnull (1, 2))) coap_rx(coap_req_data_t *req, coap_node_t *root); // <- server entry point!

extern const coap_node_t wellknown_uri;

#endif	/* ZCOAP_SERVER_H */
