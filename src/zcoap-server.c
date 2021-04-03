/*
 * File:   zcoap.c
 * Author: Michael Sandstedt
 *
 * Created on March 31, 2018, 1:24 PM
 */

#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "zcoap-server.h"

#define MIN(_a, _b) (_a < _b ? _a : _b)
#define NELM(_array) (sizeof(_array) / sizeof(_array[0]))

#define COAP_VERSION 1
#define COAP_MAX_TKL 8
#define COAP_PAYLOAD_MARKER 0xFF
#define COAP_PL_MARKER_SIZE 1
#define COAP_TOKEN(_coap_msg) ((uint8_t *)((coap_msg_t *)(_coap_msg) + 1))
#define COAP_OPTS(_coap_msg) ((uint8_t *)((coap_msg_t *)(_coap_msg) + 1) + (_coap_msg)->tkl)
#define HREF_KEY "href=/"


#define RESPONSE_FMT_U16 "%u"
#define RESPONSE_FMT_I16 "%d"
#define RESPONSE_FMT_U32 "%" PRIu32
#define RESPONSE_FMT_I32 "%" PRId32
#define RESPONSE_FMT_U64 "%" PRIu64
#define RESPONSE_FMT_I64 "%" PRId64
#define RESPONSE_FMT_FLOAT "%.8g"

enum {
    CBOR_MAJOR_TYPE_UNSIGNED = 0,
    CBOR_MAJOR_TYPE_NEGATIVE = 1,
    CBOR_MAJOR_TYPE_BYTE_STRING = 2,
    CBOR_MAJOR_TYPE_TEXT_STRING = 3,
    CBOR_MAJOR_TYPE_ARRAY = 4,
    CBOR_MAJOR_TYPE_MAP = 5,
    CBOR_MAJOR_TYPE_TAG = 6,
    CBOR_MAJOR_TYPE7 = 7, // float and no-content
};

enum {
    // CBOR Major Type 0/1 Integer encoding
    CBOR_ADD_INFO_UINT8 = 24,
    CBOR_ADD_INFO_UINT16 = 25,
    CBOR_ADD_INFO_UINT32 = 26,
    CBOR_ADD_INFO_UINT64 = 27,
    // CBOR Major Type 7 Simple value encoding
    CBOR_ADD_INFO_FALSE = 20,
    CBOR_ADD_INFO_TRUE = 21,
    CBOR_ADD_INFO_NULL = 22,
    CBOR_ADD_INFO_UNDEF = 23,
    CBOR_ADD_INFO_SIMPLE_VALUE_BYTE = 24,
    // CBOR Major Type 7 Float encoding
    CBOR_ADD_INFO_HALF = 25,
    CBOR_ADD_INFO_SINGLE = 26,
    CBOR_ADD_INFO_DOUBLE = 27,
    // CBOR Major Type 7 Indefinite length break
    CBOR_ADD_INFO_BREAK = 31,
};

#pragma pack(push)
typedef struct cbor_s {
    uint8_t add : 5; // additional data
    uint8_t type : 3; // major type
    uint8_t payload[0]; // optional payload
} cbor_t;

#define IEEE754_HALF_BITS_FRACTION 10
#define IEEE754_HALF_BITS_EXPONENT 5
typedef struct half_s {
    uint16_t fraction : 10;
    uint16_t exponent : 5;
    uint16_t sign : 1;
} half_t;
#pragma pack(pop)

/**
 * Perform a quick runtime arithmetic check to determine whether the host
 * environment is little endian.  If it is, return true.  Else, return false.
 *
 * @return true if host environment is little endian, else false
 */
static bool host_is_little_endian(void)
{
    uint16_t host_short = 42;
    if (host_short != *(uint8_t *)&host_short) {
        return false;
    } else {
        return true;
    }
}

/**
 * Convert a 16-bit integer to network byte order.
 *
 * @param hostshort 16-bit integer in host byte order
 * @param 16-bit integer in network byte order
 */
static uint16_t
#ifdef __GNUC__
__attribute__((const))
#endif
ZCOAP_HTONS(uint16_t hostshort)
{
    if (!host_is_little_endian()) {
        return hostshort; // no conversion necessary
    }
    uint16_t netshort;
    uint8_t * const p = (uint8_t *)&hostshort;
    uint8_t * const q = (uint8_t *)&netshort;
    q[1] = p[0];
    q[0] = p[1];
    return netshort;
}

/**
 * Convert a 32-bit integer to network byte order.
 *
 * @param hostshort 32-bit integer in host byte order
 * @param 32-bit integer in network byte order
 */
static uint32_t
#ifdef __GNUC__
__attribute__((const))
#endif
ZCOAP_HTONL(uint32_t hostlong)
{
    if (!host_is_little_endian()) {
        return hostlong; // no conversion necessary
    }
    uint32_t netlong;
    uint8_t * const p = (uint8_t *)&hostlong;
    uint8_t * const q = (uint8_t *)&netlong;
    q[3] = p[0];
    q[2] = p[1];
    q[1] = p[2];
    q[0] = p[3];
    return netlong;
}

/**
 * Convert a 64-bit integer to network byte order.
 *
 * @param hostllong 64-bit integer in host byte order
 * @param 64-bit integer in network byte order
 */
static uint64_t
#ifdef __GNUC__
__attribute__((const))
#endif
ZCOAP_HTONLL(uint64_t hostllong)
{
    if (!host_is_little_endian()) {
        return hostllong; // no conversion necessary
    }
    uint64_t netllong;
    uint8_t * const p = (uint8_t *)&hostllong;
    uint8_t * const q = (uint8_t *)&netllong;
    q[7] = p[0];
    q[6] = p[1];
    q[5] = p[2];
    q[4] = p[3];
    q[3] = p[4];
    q[2] = p[5];
    q[1] = p[6];
    q[0] = p[7];
    return netllong;
}

/**
 * Convert a half-precision float to network byte order.
 *
 * @param hostfloat half-precision IEEE-754 float in host byte order
 * @param half-precision IEEE-754 float in network byte order
 */
static half_t
#ifdef __GNUC__
__attribute__((const))
#endif
ZCOAP_HTONH(half_t hostfloat)
{
    if (!host_is_little_endian()) {
        return hostfloat; // no conversion necessary
    }
    half_t netfloat;
    uint8_t * const p = (uint8_t *)&hostfloat;
    uint8_t * const q = (uint8_t *)&netfloat;
    q[1] = p[0];
    q[0] = p[1];
    return netfloat;
}

/**
 * Convert a single-precision float to network byte order.
 *
 * @param hostfloat single-precision IEEE-754 float in host byte order
 * @param single-precision IEEE-754 float in network byte order
 */
static float
#ifdef __GNUC__
__attribute__((const))
#endif
ZCOAP_HTONF(float hostfloat)
{
    if (!host_is_little_endian()) {
        return hostfloat; // no conversion necessary
    }
    float netfloat;
    uint8_t * const p = (uint8_t *)&hostfloat;
    uint8_t * const q = (uint8_t *)&netfloat;
    q[3] = p[0];
    q[2] = p[1];
    q[1] = p[2];
    q[0] = p[3];
    return netfloat;
}

/**
 * Convert a double-precision float to network byte order.
 *
 * @param hostdouble double-precision IEEE-754 float in host byte order
 * @param double-precision IEEE-754 float in network byte order
 */
static ZCOAP_DOUBLE
#ifdef __GNUC__
__attribute__((const))
#endif
ZCOAP_HTOND(ZCOAP_DOUBLE hostdouble)
{
    if (!host_is_little_endian()) {
        return hostdouble; // no conversion necessary
    }
    ZCOAP_DOUBLE netdouble;
    uint8_t * const p = (uint8_t *)&hostdouble;
    uint8_t * const q = (uint8_t *)&netdouble;
    q[7] = p[0];
    q[6] = p[1];
    q[5] = p[2];
    q[4] = p[3];
    q[3] = p[4];
    q[2] = p[5];
    q[1] = p[6];
    q[0] = p[7];
    return netdouble;
}

// host-to-net functions are inherently bidirectional
// and useable for net-to-host.  So simply use these.
#define ZCOAP_NTOHS ZCOAP_HTONS
#define ZCOAP_NTOHL ZCOAP_HTONL
#define ZCOAP_NTOHLL ZCOAP_HTONLL
#define ZCOAP_NTOHH ZCOAP_HTONH
#define ZCOAP_NTOHF ZCOAP_HTONF
#define ZCOAP_NTOHD ZCOAP_HTOND

/**
 * Convert from IEEE-754 half precision to single precision.
 */
static float
#ifdef __GNUC__
__attribute__((const))
#endif
half_to_single(half_t half)
{
    const unsigned HALF_EXP_NAN = (1 << IEEE754_HALF_BITS_EXPONENT) - 1;
#ifdef NAN
    if (half.exponent == HALF_EXP_NAN && half.fraction) {
        return NAN;
    } else
#endif /* NAN */
    if (half.exponent == HALF_EXP_NAN && half.sign) {
        return -INFINITY;
    } else if (half.exponent == HALF_EXP_NAN && !half.sign) {
        return INFINITY;
    } else if (half.exponent) { // Normal half precision.
        int exponent = half.exponent - 15; // excess 15
        int fraction = half.fraction |= 0x400; // add leading 1
        if (half.sign) {
            fraction = -fraction;
        }
        return ldexpf(fraction, exponent);
    } else { // Denormal half precision.
        int fraction;
        if (half.sign) {
            fraction = -fraction;
        }
        return ldexpf(fraction, -15 - 10);
    }
}

typedef struct href_filter_s {
    char *str;
    size_t len;
    bool wildcard;
} href_filter_t;

/**
 * Determine whether name and href_filter are a match.  Note that per RFC6690,
 * the href filter may use a wildcard.
 *
 * @param name path name to match
 * @param href_filter href filter object
 * @return true if match, false if no match
 */
static bool
#ifdef __GNUC__
__attribute__((pure))
#endif
href_match(const char* name, const href_filter_t* href_filter)
{
    if (href_filter->wildcard) {
        if (strlen(name) >= href_filter->len && !strncmp(href_filter->str, name, href_filter->len)) {
            return true;
        }
    } else {
        if (strlen(name) == href_filter->len && !strncmp(href_filter->str, name, href_filter->len)) {
            return true;
        }
    }
    return false;
}

// Copies of coap_handler_t signature, but with differing nonnull rules.
// This allows passage of different parameters when we wish to access handlers'
// alternate function: extraction of node content type.
#ifdef __GNUC__
typedef void __attribute__((nonnull (1, 8))) (*ct_counter)(ZCOAP_METHOD_SIGNATURE);
typedef void __attribute__((nonnull (1, 9))) (*ct_extractor)(ZCOAP_METHOD_SIGNATURE);
#else
typedef void (*ct_counter)(ZCOAP_METHOD_SIGNATURE);
typedef void (*ct_extractor)(ZCOAP_METHOD_SIGNATURE);
#endif

 /**
 * snprintf wrapper.  Write up to *remain characters into *buf.  Advance *buf
 * past all characters written.  Decrement *remain by the number of characters
 * written.  Increment *total by the number of characters that would have been
 * been written had *remain been sufficient to hold all formatted printing.
 *
 * @param total (in/out) counter to increment by the number of characters needed to fully print fmt
 * @param buf (in/out) buffer to write into; advanced by the number of characters written
 * @param remain (in/out) number of characters remaining in buf; decremented by the number of characters written
 * @param fmt printf format string
 * @param ... printf arguments
 */
static void SNPRINTF(size_t *total, char ** const buf, size_t *remain, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    size_t len = ZCOAP_VSNPRINTF(*buf, *remain, fmt, ap);
    va_end(ap);
    *total += len;
    if (len < *remain) {
        *buf += len;
        *remain -= len;
    }  else {
        *buf += *remain;
        *remain = 0;
    }
}

/**
 * Compare two content format designators.
 *
 * @param a content format designator
 * @param b content format designator
 * @return 1 if a>b, 0 if a==b, -1 if a<b
 */
static int ct_cmp(const void * const a, const void * const b)
{
    const coap_ct_t *cta = (const coap_ct_t *)a;
    const coap_ct_t *ctb = (const coap_ct_t *)b;
    if (*cta < *ctb) {
        return -1;
    } else if (*cta > *ctb) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * Invoke a node's methods in 'ct_extractor' mode, passing a ct array for each
 * method to set supported content-type flags as approprate. Once the flags
 * are extracted, print corresponding content-type designators to the output
 * buffer for inclusion in /.well-known/core.  Print output is in accordance
 * with RFC6690, constructed as to be appended to a /.well-known/core path
 * description.  For instance, if URI /sensors supports JSON format, we will
 * output ';ct=50'.  From /.well-known/core, this will appear as:
 *
 * </sensors>;ct=50
 *
 * @param node CoAP server node for which to produce RFC6690-compliant ct= strings
 * @param len (in/out) encremented with length printed to buf
 * @param buf (in/out) buffer pointer to print to and increment
 * @param remain (in/out) remaining bytes in buf; decremented with each printed character
 */
static void print_ct(coap_node_t * const node, size_t * const len, char ** const buf, size_t * const remain)
{
    // Count content format designators.
    size_t count = 0;
    if (node->GET) {
        (*(ct_counter)node->GET)(node, NULL, 0, NULL, 0, 0, NULL, &count, NULL);
    }
    if (node->PUT) {
        (*(ct_counter)node->PUT)(node, NULL, 0, NULL, 0, 0, NULL, &count, NULL);
    }
    if (node->POST) {
        (*(ct_counter)node->POST)(node, NULL, 0, NULL, 0, 0, NULL, &count, NULL);
    }
    if (node->DEL) {
        (*(ct_counter)node->DEL)(node, NULL, 0, NULL, 0, 0, NULL, &count, NULL);
    }

    // Extract content format designators.
    ZCOAP_ASSERT(count  * sizeof(coap_ct_t) < ZCOAP_MAX_BUF_SIZE);
#ifdef __GNUC__
    coap_ct_t ct[count];
#else
    coap_ct_t ct[ZCOAP_MAX_BUF_SIZE / sizeof(coap_ct_t)];
#endif
    if (node->GET) {
        (*(ct_extractor)node->GET)(node, NULL, 0, NULL, 0, 0, NULL, NULL, ct);
    }
    if (node->PUT) {
        (*(ct_extractor)node->PUT)(node, NULL, 0, NULL, 0, 0, NULL, NULL, ct);
    }
    if (node->POST) {
        (*(ct_extractor)node->POST)(node, NULL, 0, NULL, 0, 0, NULL, NULL, ct);
    }
    if (node->DEL) {
        (*(ct_extractor)node->DEL)(node, NULL, 0, NULL, 0, 0, NULL, NULL, ct);
    }

    // Sort and print, suppressing duplicates.
    qsort(ct, count, sizeof(ct[0]), &ct_cmp);
    coap_ct_t prev = ZCOAP_FMT_SENTINEL;
    for (size_t i = 0; i < count; ++i) {
        if (ct[i] != prev) {
            SNPRINTF(len, buf, remain, ";ct=%u", ct[i]);
            prev = ct[i];
        }
    }
}

/**
 * Data interface for iter_wellknown_core.
 *
 * @param pwd present working directory; the path preceding node
 * @param href_filter filter against which to match as in a .well-known/core?href= filtered query
 * @param parent_href_match sticky flag to tell us if a parent path segment matched href; if so, we inherit match
 * @param len (in/out) number of characters that would have been printed had remain been large enough
 * @param buf (in/out) buffer to print into
 * @param remain (in/out) number of bytes available in buf
 */
typedef struct iter_wellknown_core_data_s {
    const char * const pwd;
    const href_filter_t * const href_filter;
    const bool parent_href_match;
    size_t * const len;
    char ** const buf;
    size_t * const remain;
} iter_wellknown_core_data_t;

static coap_code_t iter_wellknown_core(coap_node_t * const node, const void *data); // forward declaration

/**
 * Recursive URI tree iterator for performing a depth-first walk of the URI tree
 * and dumping an RFC6690-compliant .well-known/core response.
 *
 * @param node present node in the tree from which to proceed with the recursive dump
 * @data iter_wellknown_core_data_t
 */
static coap_code_t iter_wellknown_core(coap_node_t * const node, const void *data)
{
    if (!node || !data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    const iter_wellknown_core_data_t * const pdata = (iter_wellknown_core_data_t *)data;
    bool match = pdata->parent_href_match; // always inherit parent match
    do {
        if (node->name == NULL) {
            break; // suppress output of unnamed elements
        } else if (pdata->href_filter->str) {
            match = match || href_match(node->name, pdata->href_filter);
            if (!match) {
                break;
            }
        } else if (!node->GET && !node->PUT && !node->POST && !node->DEL) {
            break; // suppress output of nodes with no methods
        } else if (node->name[0] == '.' || node->hidden) {
            return 0; // suppress output of hidden tree segments
        }
        SNPRINTF(pdata->len, pdata->buf, pdata->remain, "<%s%s>", pdata->pwd, node->name);
        print_ct(node, pdata->len, pdata->buf, pdata->remain);
        SNPRINTF(pdata->len, pdata->buf, pdata->remain, ",");
    } while (0);
    const size_t pwdlen = strlen(pdata->pwd);
    const size_t cplen = node->name ? strlen(node->name) : 0;
    //Note, Visual Studio's cl.exe doesn't support VLAs!  Annoying.
    //https://stackoverflow.com/questions/5246900/enabling-vlas-variable-length-arrays-in-ms-visual-c
#ifdef __GNUC__
    // We do not bounds-check for this stack buffer allocation.  Unlike
    // situatiions where the client is injecting data of variable length, we
    // have full control of our tree and path lengths.  Thus we presume that
    // pwd is of reasonable length and is safe to push on the stack.
    char cpbuf[pwdlen + cplen + 1 /* '/' */ + 1 /* '\0' */];
#else
    char *cpbuf = ZCOAP_ALLOCA(pwdlen + cplen + 1 /* '/' */ + 1 /* '\0' */);
    if (cpbuf == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
#endif /* __GNUC__ */

    ZCOAP_MEMCPY(cpbuf, pdata->pwd, pwdlen);
    ZCOAP_MEMCPY(cpbuf + pwdlen, node->name, cplen);
    cpbuf[pwdlen + cplen] = '/';
    cpbuf[pwdlen + cplen + 1] = '\0';
    const iter_wellknown_core_data_t cdata = {
        .pwd = cpbuf,
        .href_filter = pdata->href_filter,
        .parent_href_match = match,
        .len = pdata->len,
        .buf = pdata->buf,
        .remain = pdata->remain,
    };
    if (node->children) {
        for (coap_node_t * const *c = node->children; *c != NULL; ++c) {
            coap_node_t child = **c;
            child.parent = node;
            child.singleton = node->singleton; // singleton is inherited
            iter_wellknown_core(&child, &cdata);
        }
    }
    if (node->gen) {
        (*node->gen)(node, &iter_wellknown_core, &cdata);
    }
#ifndef __GNUC__
    ZCOAP_ALLOCA_FREE(cpbuf);
#endif /* __GNUC__ */
    return 0;
}

/**
 * Recursively call iter_wellknown_core for an RFC-6690-compliant dump of our
 * URI tree.  That is, produce /.well-known/core per RFC-6690.
 *
 * @param buf buf to print into
 * @param number of bytes available in buf
 * @param root root node of tree
 * @param href_filter filter for matching path segments
 * @return number of characters, excluding '\0', that would have been printed had remain been large enough
 */
static size_t snprintf_wellknown_core(char *buf, size_t remain, coap_node_t root, const href_filter_t * const href_filter)
{
    size_t len = 0;
    const iter_wellknown_core_data_t iter_data = {
        .pwd = "",
        .href_filter = href_filter,
        .parent_href_match = false,
        .len = &len,
        .buf = &buf,
        .remain = &remain,
    };
    root.singleton = true; // Project singleton characteristic into children.
    iter_wellknown_core(&root, &iter_data);
    return len;
}

/**
 * Compare two options by value.  Use for bsearch of pre-sorted options arrays.
 * Note that due to the delta encoding, all in-payload options are by definition
 * sorted.
 *
 * @param a option
 * @param b option
 * @return 1 if a>b, 0 if a==b, -1 if a<b
 */
static int opt_cmp(const void * const a, const void * const b)
{
    const coap_opt_t *opta = a;
    const coap_opt_t *optb = b;
    if (opta->num < optb->num) {
        return -1;
    } else if (opta->num > optb->num) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * Find an href filter query option key=value pair if any is present in opts.
 *
 * @param nopts number options
 * @param opts options array to search
 * @return href_filter_t structure
 */
static href_filter_t get_href_filter(const size_t nopts, const coap_msg_opt_t opts[])
{
    /* Per RFC6690:
     *
     * A server implementing this specification MAY recognize the query part
     * of a resource discovery URI as a filter on the resources to be
     * returned.  The path and query components together should conform to
     * the following level-4 URI Template [RFC6570]:
     *
     * /.well-known/core{?search*}
     *
     * where the variable "search" is a 1-element list that has a single
     * name/value pair.
     *
     * Hence, we need only search for a single URI query option.
     */

    href_filter_t rv = { 0 };
    // Find *an* occurrence of a URI query option.  It may not be the first,
    // but per above, a client specifying more than one URI query for the
    // .well-known/core URI is violating RFC6690.
    const coap_msg_opt_t key = { .num = COAP_OPT_URI_QUERY };
    coap_msg_opt_t *a_query_opt = bsearch(&key, opts, nopts, sizeof(opts[0]), &opt_cmp);
    if (!a_query_opt) {
        return rv;
    }
    if (!strncmp(a_query_opt->val, HREF_KEY, MIN(a_query_opt->len, strlen(HREF_KEY)))) {
        rv.str = (char *)a_query_opt->val + strlen(HREF_KEY);
        rv.len = a_query_opt->len - strlen(HREF_KEY);
        if (rv.len && rv.str[rv.len - 1] == '*') {
            rv.wildcard = true;
            --rv.len;
        }
    }
    return rv;
}

/**
 * Stable comparison for options.  Compares both option number (first) and
 * current memory address (second) to achieve stable sort by preserving relative
 * order for like-numbered options
 *
 * @param a option
 * @param b option
 * @return 1 for a>b, 0 for a==b, -1 for a<b
 */
static int opt_scmp(const void * const a, const void * const b)
{
    const coap_opt_t *opta = *(const coap_opt_t **)a;
    const coap_opt_t *optb = *(const coap_opt_t **)b;
    if (opta < optb || opta->num < optb->num) {
        return -1;
    } else if (opta > optb || opta->num > optb->num) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * Stable sort options in preparation for in-message encoding.  Note that due to
 * the delta encoding, options must be sorted.  Furthermore, to preserve
 * relative position of like-numbered options (e.g. to preserve path segment
 * ordering), stable stort must be employed.
 *
 * @param nopts number of options to stort
 * @param opts options to sort
 * @param sorted (out) sorted options
 */
static void stable_sort_opts(const size_t nopts, const coap_opt_t opts[], const coap_opt_t *sorted[])
{
    // STABLE sort; caller must allocate sorted.
    if (nopts == 0) {
        return;
    }
    ZCOAP_ASSERT(opts != NULL && sorted != NULL);
    for (size_t i = 0; i < nopts; ++i) {
        sorted[i] = &opts[i]; // initialize pointers
    }
    qsort(sorted, nopts, sizeof(sorted[0]), &opt_scmp);
}

/**
 * Stuff an option, using delta encoding for option number.
 *
 * @param acc accumulated option number
 * @param optnum number of option to stuff
 * @param optlen option value length
 * @param opt option value
 * @param buf location to stuff option
 * @return buf advanced past the stuffed option
 */
static uint8_t *stuff_option(uint32_t * const acc, uint16_t optnum, uint16_t optlen, const void * const opt, uint8_t *buf)
{
    uint16_t delta = optnum - *acc;
    *acc += delta;
    *buf = 0;
    size_t opd_ex_bytes;
    if (delta < 13) {
        *buf |= delta << 4;
        opd_ex_bytes = 0;
    } else if (delta < 269) {
        *buf |= 13 << 4;
        *(buf + 1) = delta - 13;
        opd_ex_bytes = 1;
    } else {
        *buf |= 14 << 4;
        uint16_t net = ZCOAP_HTONS(delta - 269);
        ZCOAP_MEMCPY(buf + 1, &net, sizeof(net));
        opd_ex_bytes = 2;
    }
    size_t opl_ex_bytes;
    if (optlen < 13) {
        *buf |= optlen;
        opl_ex_bytes = 0;
    } else if (optlen < 269) {
        *buf |= 13;
        *(buf + 1 + opd_ex_bytes) = optlen - 13;
        opl_ex_bytes = 1;
    } else {
        *buf |= 14;
        uint16_t net = ZCOAP_HTONS(optlen - 269);
        ZCOAP_MEMCPY(buf + 1 + opd_ex_bytes, &net, sizeof(net));
        opl_ex_bytes = 2;
    }
    buf += 1 + opd_ex_bytes + opl_ex_bytes;
    ZCOAP_MEMCPY(buf, opt, optlen);
    buf += optlen;
    return buf;
}

/**
 * Use delta encoding to stuff options into buf.
 *
 * @param buf buffer into which to stuff options
 * @param nopts number of options to stuff
 * @param opts options to stuff
 * @return buf advanced past stuffed options
 */
static uint8_t *stuff_options(uint8_t *buf, size_t nopts, const coap_opt_t opts[])
{
    // As awkward as it is, we must pre-sort our options in order to build a
    // CoAP options payload.  Option-number-delta is unsigned, so option numbers
    // must be monotonically increasing as we traverse the packet.
    //

    // To ensure robustness, this function preforms the sort itself.

#ifdef __GNUC__
    // Allocate a temp pointer array on the stack.  This is for an outgoing
    // message, not an incoming message.  Thus we are not concerned about
    // a client injecting data that will lead to our stack overflow - we are
    // in full control of this message and are confident the options array
    // is of reasonable size.  Thus we do not bounds check.
    const coap_opt_t *sorted[nopts];
#else
    // Non-C99 platforms don't permit a variable-length array.  So we must
    // statically allocate and must choose some reasonable limit.  If our
    // outgoing message exceeds this limit, we must simply issue an error
    // response.
    if (nopts > ZCOAP_MAX_PAYLOAD_OPTS) {
        return NULL;
    }
    const coap_opt_t *sorted[ZCOAP_MAX_PAYLOAD_OPTS];
#endif /* __GNUC__ */

    stable_sort_opts(nopts, opts, sorted);
    uint32_t opt_acc = 0;
    for (size_t i = 0; i < nopts; ++i) {
        buf = stuff_option(&opt_acc, sorted[i]->num, sorted[i]->len, sorted[i]->val, buf);
    }
    return buf;
}

/**
 * Pre-sort the passed options and compute their delta-encoded length.
 *
 * @param nopts number of options
 * @param opts options
 * @return delta-encoded length in bytes
 */
static size_t opt_sec_len(const size_t nopts, const coap_opt_t opts[])
{
    // As awkward as it is, we must pre-sort our options in order to determine
    // the length of the CoAP options payload.  Option-number-delta is unsigned,
    // so option numbers must be monotonically increasing as we traverse the
    // packet.
    // To ensure robustness, this function preforms the sort itself.

#ifdef __GNUC__
    const coap_opt_t *sorted[nopts]; // allocate temp pointer array on the stack
#else
    ZCOAP_ASSERT(nopts <= ZCOAP_MAX_PAYLOAD_OPTS);
    const coap_opt_t *sorted[ZCOAP_MAX_PAYLOAD_OPTS];
#endif /* __GNUC__ */

    stable_sort_opts(nopts, opts, sorted);
    size_t len = 0;
    uint32_t num_acc = 0;
    for (size_t i = 0; i < nopts; ++i) {
        ++len;
        uint16_t delta = sorted[i]->num - num_acc;
        if (delta >= 269) {
            len += 2;
        } else if (delta >= 13) {
            ++len;
        }
        num_acc += delta;
        if (sorted[i]->len >= 269) {
            len += 2;
        } else if (sorted[i]->len >= 13) {
            ++len;
        }
        len += sorted[i]->len;
    }
    return len;
}

/**
 * Discard a CoAP request when the server plans to undertake no further action
 * for a particular request.  When this is called, no response will be issued
 * to the requesting client.
 *
 * @param req CoAP request to discard
 */
static void
#ifdef __GNUC__
__attribute__((nonnull (1)))
#endif
coap_discard(coap_req_data_t* const req)
{
    ZCOAP_ASSERT(req != NULL);
    if (req->discard == NULL) {
        return;
    }
    (*req->discard)(req);
}

/**
 * Issue an immediate (non-piggy-backed) ACK to req. On successful
 * ACK transmission, set req->msg->type to non-confirmable.  This
 * will illicit non-piggy-backed response from coap_rsp and prevent
 * duplicate ACK.
 *
 * @param req CoAP request to ACK
 * @return 0 on success, non-zero on error
 */
void coap_ack(coap_req_data_t* const req)
{
    ZCOAP_ASSERT(   req != NULL
                 && req->msg != NULL
                 && req->len >= sizeof(coap_msg_t)
                 && req->responder != NULL);
    if (req->msg->type == COAP_TYPE_NON_CONFIRMABLE) {
        return; // no ACK needed
    }
    ZCOAP_ASSERT(req->msg->type == COAP_TYPE_CONFIRMABLE);
    coap_msg_t ack;
    ZCOAP_MEMCPY(&ack, req->msg, sizeof(ack));
    ack.tkl = 0;
    ack.type = COAP_TYPE_ACK;
    ack.code.code_class = 0;
    ack.code.code_detail = 0;
    ((*req->responder)(req, sizeof(ack), &ack));
    // Note transmission of ACK to illicit non-piggy-backed
    // response behavior in coap_rsp().
    req->state.acked = true;
}

/**
 * Compute the response PDU size based upon the passed response options and
 * payload length, and with consderation of the passed request and its enclosed
 * variable-length token, which we must return to the requesting client.
 *
 * @param req CoAP request to which to respond
 * @param nopts number of response message options
 * @param opts response message options
 * @param pl_len response payload length
 * @param rsp_len (out) computed response length
 * @return 0 on success, appropriate errno on error
 */
static int compute_rsp_pdu_len(coap_req_data_t * const req, const size_t nopts, const coap_opt_t opts[], const size_t pl_len, size_t *rsp_len)
{
    // Check arguments.
    if (   req == NULL
        || req->msg == NULL
        || req->len < sizeof(coap_msg_t)
        || req->len < sizeof(coap_msg_t) + req->msg->tkl
        || req->msg->tkl > COAP_MAX_TKL
        || rsp_len == NULL) {
        return EINVAL;
    }
    // Determine how big our response PDU will be.
    *rsp_len = sizeof(coap_msg_t) + req->msg->tkl;
    *rsp_len += opt_sec_len(nopts, opts);
    if (pl_len) {
        *rsp_len += COAP_PL_MARKER_SIZE; // for payload marker
        *rsp_len += pl_len; // for the payload itself
    }
    return 0;
}

/**
 * Populate a CoAP response header, token and options array for the passed CoAP
 * request, enclosing the passed response code and options array.
 *
 * @param req CoAP request for which a response must be constructed
 * @param code CoAP response code
 * @param nopts number of response message options
 * @param opts response message options
 * @param rsp (out) CoAP response buffer to write into - must be large enough to hold token and options!
 * @return pointer to payload marker write location on success, NULL on failure
 */
static uint8_t *populate_rsp_header(coap_req_data_t * const req, const coap_code_t code, const size_t nopts, const coap_opt_t opts[], coap_msg_t *rsp)
{
    // Check arguments.
    if (req == NULL || req->msg == NULL || rsp == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return NULL;
    }
    // Copy message header and token.
    ZCOAP_MEMCPY(rsp, req->msg, sizeof(coap_msg_t) + req->msg->tkl);
    if (req->state.obs == true) {
        // Observation responses must be confirmed.  This allows us to detect
        // disappearance of the observer.
        rsp->type = COAP_TYPE_CONFIRMABLE;
    } else if (req->msg->type == COAP_TYPE_CONFIRMABLE && !req->state.acked) {
        rsp->type = COAP_TYPE_ACK;
    } else {
        rsp->type = COAP_TYPE_NON_CONFIRMABLE;
        rsp->msg_ID = 0;
        // We are not windowing message ID on this layer (all outgoing are
        // non-confirmable).  Hence message ID of 0 is fine.
    }
    // Insert code, options and payload.
    ZCOAP_MEMCPY(&rsp->code, &code, sizeof(rsp->code));
    uint8_t *opt_ptr = COAP_OPTS(rsp);
    return stuff_options(opt_ptr, nopts, opts);
}

/**
 * Return the URI tree root for the passed node.
 *
 * @param node node for which to return the tree root
 * @return URI tree root node
 */
static const coap_node_t *get_root(const coap_node_t * const node)
{
    const coap_node_t *root = node;
    while (root->parent) {
        root = root->parent;
    }
    return root;
}

/**
 * Traverse the URI tree upward toward the root to find and acquire a node lock.
 *
 * @param node URI tree node from which to traverse upward to locate and acquire a lock
 */
static void coap_lock(const coap_node_t *node)
{
    while (!node->lock && node->parent) {
        node = node->parent;
    }
    if (node->lock) {
        ZCOAP_LOCK(node->lock);
    }
}

/**
 * Traverse the URI tree upward toward the root to find and reqlinquish a node lock.
 *
 * @param node URI tree node from which to traverse upward to locate and relinquish a lock
 */
static void coap_unlock(const coap_node_t *node)
{
    while (!node->lock && node->parent) {
        node = node->parent;
    }
    if (node->lock) {
        ZCOAP_UNLOCK(node->lock);
    }
}

/*********** Begin RFC7641 observation request utility functions. ************/

/**
 * Write an appropriately formatted observe option with value pointing to the
 * passed sequence number.  Reorder sequence for big-endian transmission.
 *
 * @param seq (in, out) sequence number to convert to big-endian and enclose in the option structure
 * @param opt (out) option structure to write into
 */
static void
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
build_observe_option(coap_obs_seq_t *seq, coap_opt_t *opt)
{
    ZCOAP_ASSERT(seq != NULL && opt != NULL);
    opt->num = COAP_OPT_OBSERVE;
    *seq = ZCOAP_HTONL(*seq);
    opt->len = *seq <= 0xFF ? 1 : *seq <= 0xFFFF ? 2 : 3;
    opt->val = (uint8_t *)seq + (sizeof(*seq) - opt->len);
}

#define COAP_OBS_REGISTER 0
#define COAP_OBS_DEREGISTER 1

#define MAP_IDX_TO_BIT_IDX(_i) ((_i) << (ZCOAP_WORD_ALIGN_SHIFT + 3))
#define BIT_IDX_TO_MAP_IDX(_i) ((_i) >> (ZCOAP_WORD_ALIGN_SHIFT + 3))
#define BIT_IDX_TO_BIT_POS(_i) ((_i) & ((1 << (ZCOAP_WORD_ALIGN_SHIFT + 3)) - 1))

/**
 * Compare two instances of the coap_subscriber_t structure based upon the client
 * endpoint enclosed in each and evaluated based upon an enclosed endpoint
 * comparator.
 *
 * @param _a subscriber a subscription map
 * @param _b subscriber b subscription map
 * @return -1 if endpoint a < endpoint b, 1 if endpoint a > endpoint b, 0 if endpoint a == endpoint b
 */
static int sub_map_cmp(const void * const _a, const void * const _b)
{
    ZCOAP_ASSERT(_a != NULL && _b != NULL);
    coap_subscriber_t *a = *(coap_subscriber_t **)_a;
    coap_subscriber_t *b = *(coap_subscriber_t **)_b;
    ZCOAP_ASSERT(a->cmp != NULL);
    int rv = 0;
    if ((rv = (*a->cmp)(a->endpoint, b->endpoint)) != 0) {
        return rv;
    }
    return 0;
}

/**
 * Compare two instances of the coap_sub_t structure based upon the enclosed
 * subscriber endpoint and subscription token.
 *
 * @param _a subscription a
 * @param _b subscription b
 * @return -1 if a < b, 1 if a > b, 0 if a == b
 */
static int sub_tok_cmp(const void * const _a, const void * const _b)
{
    ZCOAP_ASSERT(_a != NULL && _b != NULL);
    coap_sub_t *a = *(coap_sub_t **)_a;
    coap_sub_t *b = *(coap_sub_t **)_b;
    ZCOAP_ASSERT(a->subscriber != NULL && b->subscriber != NULL);
    int rv = 0;
    coap_subscriber_t *suba = a->subscriber;
    coap_subscriber_t *subb = b->subscriber;
    ZCOAP_ASSERT(suba->cmp != NULL);
    if ((rv = (*suba->cmp)(suba->endpoint, subb->endpoint)) != 0) {
        return rv;
    }
    if (a->tkl != b->tkl) {
        return a->tkl < b->tkl ? -1 : 1;
    }
    if (a->token != b->token) {
        return a->token < b->token ? -1 : 1;
    }
    return 0;
}

/**
 * Compare two instances of the coap_sub_t structure based upon the enclosed
 * subscriber endpoint and subscription ID.  The ZCoAP server uses part of
 * the 16-bit message ID space to map subscriptions.  This way we can
 * unambiguously map confirmable response ACKs to subscriptions.
 *
 * @param _a subscription a
 * @param _b subscription b
 * @return -1 if a < b, 1 if a > b, 0 if a == b
 */
static int sub_id_cmp(const void * const _a, const void * const _b)
{
    ZCOAP_ASSERT(_a != NULL && _b != NULL);
    coap_sub_t *a = *(coap_sub_t **)_a;
    coap_sub_t *b = *(coap_sub_t **)_b;
    ZCOAP_ASSERT(a->subscriber != NULL && b->subscriber != NULL);
    int rv = 0;
    coap_subscriber_t *suba = a->subscriber;
    coap_subscriber_t *subb = b->subscriber;
    ZCOAP_ASSERT(suba->cmp != NULL);
    if ((rv = (*suba->cmp)(suba->endpoint, subb->endpoint)) != 0) {
        return rv;
    }
    if (a->id != b->id) {
        return a->id < b->id ? -1 : 1;
    }
    return 0;
}

/**
 * Find the first bit clear from right (lsb) in v.  Bit position is 1-based.
 * If no bits are clear, return 0;
 *
 * @param v integer to examine
 * @return 1-based index of first bit clear from right (lsb), or 0 if no bits are clear
 */
static unsigned ZCOAP_FF0R(unsigned v)
{
    if (v == UINT_MAX) {
        return 0; // early out
    }
    for (unsigned i = 0; i < ZCOAP_BITS_PER_WORD; ++i) {
        if (!(v & (1 << i))) {
            return i + 1; // bit position is 1-based
        }
    }
    return 0; // make the compiler happy
}

/**
 * Allocate a subscription ID from a subscriber's endpoint-specific map in the
 * subscriber table.  If the subscriber is not present in the subscriber table,
 * add it.  Record the allocated subscription ID and a reference to the
 * subscriber endpoint information in the passed subscription structure.
 *
 * Note that within the entry in the subscriber table, we will store a single
 * deep copy of the subscriber's endpoint information.  This deep copy will be
 * shared amongst all subscriptions associated with the particular subscriber
 * endpoint.
 *
 * @param map subscription map
 * @param req initiating client request
 * @param sub subscription into which deep-copy endpoint and allocated ID should be written
 * @return 0 on success, an appropriate CoAP error code on failure
 */
static coap_code_t
#ifdef __GNUC__
__attribute__((nonnull (1, 2, 3)))
#endif
alloc_sub_id(coap_sub_map_t * const map, coap_req_data_t * const req, coap_sub_t * const sub)
{
    ZCOAP_ASSERT(map != NULL && req != NULL && sub != NULL);
    coap_subscriber_t needle = { .endpoint = req->endpoint, .cmp = map->endpoint_cmp };
    coap_subscriber_t *key = &needle;
    coap_subscriber_t **_subscriber = map->subscribers ? bsearch(&key, map->subscribers, map->n_subscribers, sizeof(map->subscribers[0]), &sub_map_cmp) : NULL;
    coap_subscriber_t *subscriber = _subscriber ? *_subscriber : NULL;
    if (subscriber == NULL) {
        if (map->n_subscribers >= ZCOAP_MAX_SUBSCRIBERS) {
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: subscriber table full", __func__);
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
        coap_subscriber_t **resized = ZCOAP_REALLOC(map->subscribers, sizeof(map->subscribers[0]) * (map->n_subscribers + 1));
        if (resized == NULL) {
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: subscriber table reallocation failed", __func__);
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
        map->subscribers = resized;
        map->subscribers[map->n_subscribers] = subscriber = ZCOAP_CALLOC(1, sizeof(coap_subscriber_t));
        if (subscriber == NULL) {
            if (!map->n_subscribers) {
                ZCOAP_FREE(map->subscribers);
                map->subscribers = NULL;
            }
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: subscriber allocation failed", __func__);
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
        ZCOAP_ASSERT(req->endpoint != NULL);
        subscriber->deep_copy_endpoint = *req->endpoint; // must deep-copy subscriber endpoint information
        subscriber->endpoint = &subscriber->deep_copy_endpoint;
        subscriber->cmp = map->endpoint_cmp;
        subscriber->responder = req->responder;
        subscriber->context = req->context;
        ++map->n_subscribers;
        qsort(map->subscribers, map->n_subscribers, sizeof(map->subscribers[0]), &sub_map_cmp);
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: new subscriber=%p", __func__, subscriber);
     }
     ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: adding subscription=%p to subscriber=%p", __func__, sub, subscriber);
     for (size_t i = 0; i < NELM(subscriber->map); ++i) {
        unsigned bpos;
        if (!(bpos = ZCOAP_FF0R(subscriber->map[i]))) {
            continue;
        }
        subscriber->map[i] |= 1 << (bpos - 1);
        sub->subscriber = subscriber;
        sub->id = MAP_IDX_TO_BIT_IDX(i) + bpos - 1;
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: subscription=%p, id=%u added to subscriber=%p (map[%zu]=0x%X)", __func__, sub, sub->id, subscriber, i, subscriber->map[i]);
        return 0;
     }
     ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: failed to allocate an ID for subscription=%p", __func__, sub);
     return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
}

/**
 * Free a subscription ID in a subscriber's subscription map in the subscriber
 * table.  If after freeing the passed ID the subscriber's subscription map is
 * empty, free the subscriber's endpoint information and remove the subscriber
 * from the subscriber table.
 *
 * @param map susbscription map
 * @param sub subscription to free from its subscriber's map
 */
static void
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
free_sub_id(coap_sub_map_t *map, coap_sub_t *sub)
{
    ZCOAP_ASSERT(map != NULL && sub != NULL);
    coap_subscriber_t *key = sub->subscriber;
    coap_subscriber_t **subscriber = map->subscribers ? bsearch(&key, map->subscribers, map->n_subscribers, sizeof(map->subscribers[0]), &sub_map_cmp) : NULL;
    ZCOAP_ASSERT(subscriber != NULL);
    size_t  idx = BIT_IDX_TO_MAP_IDX(sub->id);
    ZCOAP_ASSERT(idx < NELM((*subscriber)->map));
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: freeing subscription=%p, id=%u from subscriber=%p (map[%zu]=0x%X)", __func__, sub, sub->id, *subscriber, idx, (*subscriber)->map[idx]);
    size_t bpos = BIT_IDX_TO_BIT_POS(sub->id);
    (*subscriber)->map[idx] &= ~(1 << bpos);
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: subscription=%p, id=%u freed from subscriber=%p (map[%zu]=0x%X)", __func__, sub, sub->id, *subscriber, idx, (*subscriber)->map[idx]);
    for (size_t i = 0; i < NELM((*subscriber)->map); ++i) {
        if ((*subscriber)->map[i]) {
            return; // one ore more IDs still allocated; return
        }
    }
    // No IDs allocated.  Free the subscriber.
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: freeing subscriber=%p", __func__, *subscriber);
    ZCOAP_FREE(*subscriber);
    --map->n_subscribers;
    if (map->n_subscribers) {
        const size_t idx = subscriber - map->subscribers;
        const size_t remain = map->n_subscribers - idx;
        ZCOAP_MEMMOVE(subscriber, subscriber + 1, remain * sizeof(*subscriber));
        // We do not expect ZCOAP_REALLOC to fail on shrink.
        // But if it does, we will simply retain the old buffer.
        coap_subscriber_t **resized = ZCOAP_REALLOC(map->subscribers, sizeof(map->subscribers[0]) * (map->n_subscribers));
        map->subscribers = resized ? resized : map->subscribers;
    } else {
        ZCOAP_FREE(map->subscribers);
        map->subscribers = NULL;
    }
}

static coap_code_t
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
extract_obs_seq(coap_msg_opt_t *opt, coap_obs_seq_t *seq)
{
    ZCOAP_ASSERT(opt != NULL && seq != NULL);
    if (opt->num != COAP_OPT_OBSERVE) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: not an observe option", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (opt->len > 3) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
    }
    *seq = 0;
    // 3-byte big-endian sequence number: + 4 - 3 -> copy offset is 1
    // 2-byte big-endian sequence number: + 4 - 2 -> copy offset is 2
    // 1-byte big-endian sequence number: + 4 - 1 -> copy offset is 3
    // 0-byte big-endian sequence number: + 4 - 0 -> copy offset is 4
    ZCOAP_MEMCPY((uint8_t *)seq + sizeof(seq) - opt->len, opt->val, opt->len);
    *seq = ZCOAP_NTOHL(*seq); // Observe option stores sequence big-endian.
    return 0;
}

/**
 * Locate the observer subscription map from the URI tree root for the passed node.
 *
 * @param node URI tree node for which to locate the root node observer subscription map
 * @return observer subscription map from the URI tree root
 */
static coap_sub_map_t *get_sub_map(const coap_node_t *node)
{
    return get_root(node)->tsubs;
}

/**
 * Add a subscription to the passed node for the requesting agent.
 *
 * @param req request information for the subscribing client
 * @param node (in/out) node to which to add a subscription
 * @return 0 on success, an appropriate CoAP error code on failure
 */
static coap_code_t subscribe(coap_req_data_t *req, coap_node_t * const node, coap_ct_t ct)
{
    if (req == NULL || node == NULL || node->GET == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (!node->observable) {
        return 0; // RFC7641 says we can ignore observations for URIs that do not support them.
    }
    coap_sub_map_t * const map = get_sub_map(node);
    if (!node->singleton || map == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: non-singleton node, or map is NULL", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (req->msg->tkl > COAP_MAX_TKL) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    coap_subscriber_t subscriber = { .endpoint = req->endpoint, .cmp = map->endpoint_cmp };
    coap_sub_t needle = { .node = node, .subscriber = &subscriber, .tkl = req->msg->tkl };
    ZCOAP_MEMCPY(&needle.token, COAP_TOKEN(req->msg), req->msg->tkl);
    coap_sub_t *key = &needle;
    ZCOAP_LOCK(&map->lock);
    coap_sub_t **_subscription = map->subtokmap ? bsearch(&key, map->subtokmap, map->n_subscriptions, sizeof(map->subtokmap[0]), &sub_tok_cmp) : NULL;
    coap_sub_t *subscription = _subscription ? *_subscription : NULL;
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: subscription=%p", __func__, subscription);
    if (subscription != NULL) {
        // This token is already in use.  We must de-register from the current
        // URI in case the client is switching this endpoint+token subscription
        // to a new URI.
        if (subscription->pnext != NULL) {
            *subscription->pnext = subscription->next;
        }
        ZCOAP_LOG(ZCOAP_LOG_INFO, "%s: overwriting existing subscription with token 0x%" PRIx64, __func__, subscription->token);
    } else {
        if (map->n_subscriptions >= ZCOAP_MAX_SUBSCRIPTIONS) {
            ZCOAP_UNLOCK(&map->lock);
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: subscription table full", __func__);
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
        coap_code_t coap_code;
        if ((coap_code = alloc_sub_id(map, req, &needle))) {
            ZCOAP_UNLOCK(&map->lock);
            return coap_code;
        }
        coap_sub_t **resized_toks = ZCOAP_REALLOC(map->subtokmap, sizeof(map->subtokmap[0]) * (map->n_subscriptions + 1));
        map->subtokmap = resized_toks ? resized_toks : map->subtokmap;
        coap_sub_t **resized_ids = ZCOAP_REALLOC(map->subidmap, sizeof(map->subidmap[0]) * (map->n_subscriptions + 1));
        map->subidmap = resized_ids ? resized_ids : map->subidmap;
        subscription = ZCOAP_MALLOC(sizeof(coap_sub_t));
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: allocated subscription=%p", __func__, subscription);
        if (resized_toks == NULL || resized_ids == NULL || subscription == NULL) {
            if (!map->n_subscriptions) {
                if (map->subtokmap) {
                    ZCOAP_FREE(map->subtokmap);
                    map->subtokmap = NULL;
                }
                if (map->subidmap) {
                    ZCOAP_FREE(map->subidmap);
                    map->subidmap = NULL;
                }
            }
            if (subscription) {
                ZCOAP_FREE(subscription);
                subscription = NULL;
            }
            free_sub_id(map, &needle);
            ZCOAP_UNLOCK(&map->lock);
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: subscription allocation failed", __func__);
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
        map->subtokmap[map->n_subscriptions] = map->subidmap[map->n_subscriptions] = subscription;
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: copying subscription from %p to %p", __func__, &needle, subscription);
        ZCOAP_MEMCPY(subscription, &needle, sizeof(needle));
        subscription->window_left = subscription->window_right = rand();
        ++map->n_subscriptions;
        qsort(map->subtokmap, map->n_subscriptions, sizeof(map->subtokmap[0]), &sub_tok_cmp);
        qsort(map->subidmap, map->n_subscriptions, sizeof(map->subidmap[0]), &sub_id_cmp);
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: added subscription=%p for token 0x%" PRIx64, __func__, subscription, subscription->token);
    }
    if (node->nsubs) {
        node->nsubs->pnext = &subscription->next;
    }
    subscription->next = node->nsubs; // O(1) insertion at beginning of subscription list
    subscription->pnext = &node->nsubs;
    node->nsubs = subscription;
    subscription->ct = ct;
    req->state.obs = true;
    req->state.seq = node->seq;
    ZCOAP_UNLOCK(&map->lock);
    return 0;
}

/**
 * Free the passed subscription and remove it from the passed subscription
 * map.  If after removal the any members of the map are empty, free these
 * as well.
 *
 * @param map subscirption map
 * @param sub subscription to free
 */
static void
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
free_subscription(coap_sub_map_t *map, coap_sub_t **sub)
{
    ZCOAP_ASSERT(map != NULL && sub != NULL && *sub != NULL);
    // Remove the subscription from the node.
    if ((*sub)->pnext != NULL) {
        *(*sub)->pnext = (*sub)->next;
    }
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: freeing subscription=%p, subscriber=%p", __func__, *sub, (*sub)->subscriber);
    // Free the endpoint-specific subsription ID.
    free_sub_id(map, *sub);
    // Free the subscription.
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: freed subscription=%p", __func__, *sub);
    ZCOAP_FREE(*sub);
    // Remove the subscription from the map.
    --map->n_subscriptions;
    if (map->n_subscriptions) {
        const size_t idx = sub - map->subtokmap;
        coap_sub_t **tokaddr = &map->subtokmap[idx];
        coap_sub_t **idaddr = &map->subidmap[idx];
        const size_t remain = map->n_subscriptions - idx;
        ZCOAP_MEMMOVE(tokaddr, tokaddr + 1, remain * sizeof(*tokaddr));
        ZCOAP_MEMMOVE(idaddr, idaddr + 1, remain * sizeof(*idaddr));
        // We do not expect ZCOAP_REALLOC to fail on shrink.
        // But if it does, we will simply retain the old buffer.
        coap_sub_t **resized_toks = ZCOAP_REALLOC(map->subtokmap, sizeof(map->subtokmap[0]) * (map->n_subscriptions));
        map->subtokmap = resized_toks ? resized_toks : map->subtokmap;
        coap_sub_t **resized_ids = ZCOAP_REALLOC(map->subidmap, sizeof(map->subidmap[0]) * (map->n_subscriptions));
        map->subidmap = resized_ids ? resized_ids : map->subidmap;
    } else {
        ZCOAP_FREE(map->subtokmap);
        map->subtokmap = NULL;
        ZCOAP_FREE(map->subidmap);
        map->subidmap = NULL;
    }
}

/**
 * Drop subscription to the passed node for the requesting agent.
 *
 * @param map subscription map
 * @param req request information for the subscribing client
 * @param node (in/out) node for which to drop subscription
 * @return 0 on success, an appropriate CoAP error code on failure
 */
static coap_code_t unsubscribe(coap_req_data_t *req, coap_node_t * const node)
{
    if (req == NULL || node == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_sub_map_t * const map = get_sub_map(node);
    if (map == NULL) {
        return 0; // Non-error zero return.
    }
    if (req->msg->tkl > COAP_MAX_TKL) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    coap_subscriber_t subscriber = { .endpoint = req->endpoint, .cmp = map->endpoint_cmp };
    coap_sub_t needle = { .subscriber = &subscriber, .tkl = req->msg->tkl };
    ZCOAP_MEMCPY(&needle.token, COAP_TOKEN(req->msg), req->msg->tkl);
    coap_sub_t *key = &needle;
    ZCOAP_LOCK(&map->lock);
    coap_sub_t **sub = map->subtokmap ? bsearch(&key, map->subtokmap, map->n_subscriptions, sizeof(map->subtokmap[0]), &sub_tok_cmp) : NULL;
    if (sub == NULL) {
        ZCOAP_UNLOCK(&map->lock);
        return 0; // not found; no-op
    }
    // Per RFC7641, do *not* enclose observe option on deregister (unsubscribe).
    // Hence, we do not set req->state.obs true.
    free_subscription(map, sub);
    ZCOAP_UNLOCK(&map->lock);
    return 0;
}

/**
 * Process any observe registration or de-registration options in the incoming
 * request.  If registration or deregistration succeeds, or if the node is not
 * observable, return 0 (success).  Else, return an appropriate CoAP error code.
 *
 * @param node node for which to process any observe request options
 * @param req incoming request in which to look for observe options
 * @param number of options enclosed
 * @param parsed options array
 * @return 0 on success, an appropriate CoAP error code on failure
 */
static coap_code_t process_observe_req(coap_node_t * const node, coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], coap_ct_t ct)
{
    ZCOAP_ASSERT(node != NULL && req != NULL && req->msg != NULL && req->msg->code.code_class == COAP_REQ);
    // Find *an* occurrence of an observe option.  Behavior for client
    // inclusion of multiple observe options isn't defined.  We are within
    // our rights to identify at most one.
    const coap_msg_opt_t key = { .num = COAP_OPT_OBSERVE };
    coap_msg_opt_t *observe_opt = opts ? bsearch(&key, opts, nopts, sizeof(opts[0]), &opt_cmp) : NULL;
    if (observe_opt == NULL) {
        return 0; // Non-error zero return.
    }
    if (req->msg->code.code_detail != COAP_REQ_METHOD_GET) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
    }
    coap_obs_seq_t seq;
    coap_code_t rc;
    if ((rc = extract_obs_seq(observe_opt, &seq))) {
        return rc;
    }
    switch (seq) {
        case COAP_OBS_REGISTER: {
            return subscribe(req, node, ct);
        }
        case COAP_OBS_DEREGISTER: {
            return unsubscribe(req, node);
        }
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
    }
}

/**
 * Compute the size of a subscription window.  Window size is the number of
 * oustanding ACKs.
 *
 * @param left CoAP message ID subscription window left
 * @param right CoAP message ID subscription window right
 * @return number of outstanding ACKs in the subscription window
 */
coap_msg_id_t sub_window(coap_msg_id_t left, coap_msg_id_t right)
{
    const coap_msg_id_t ZCOAP_SUB_WDW_MASK = ((1 << ZCOAP_SUB_NSTART_BITS) - 1);
    return (right - left) & ZCOAP_SUB_WDW_MASK;
}

/**
 * Determine whether the passed message ID is in the left-right window.
 *
 * @param id CoAP subscription message ID to evaluate
 * @param left CoAP message ID subscription window left
 * @param right CoAP message ID subscription window right
 * @return true if the id is in the subscription window, false if it is not
 */
static bool id_in_sub_window(coap_msg_id_t id, coap_msg_id_t left, coap_msg_id_t right)
{
     coap_msg_id_t window_size = sub_window(left, right);
     coap_msg_id_t offset = sub_window(left, id);
     return (offset < window_size);
}

/**
 * Determine whether a subscription window is full.
 *
 * @param left CoAP message ID subscription window left
 * @param right CoAP message ID subscription window right
 * @return true if the the subscription window is full
 */
static bool window_full(coap_msg_id_t left, coap_msg_id_t right)
{
    coap_msg_id_t window_size = sub_window(left, right);
    return window_size == ZCOAP_SUB_NSTART;
}

/**
 * Handle an incoming ACK.  ACKs are only for our transmitted, confirmable
 * observation responses.  If the ACK matches a subscription, update the
 * subscription message ID window to reflect we received the ACK.
 *
 * Discard request data when done.
 *
 * @param ack incoming ack request to evaluate
 * @param root URI tree root node
 */
static void
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
coap_handle_ack(coap_req_data_t * const ack, const coap_node_t * const root)
{
    ZCOAP_ASSERT(ack != NULL && root != NULL);
    coap_sub_map_t * const map = root->tsubs;
    ZCOAP_ASSERT(map == NULL || map->endpoint_cmp != NULL);
    if (map == NULL || map->endpoint_cmp == NULL) {
        coap_discard(ack);
        return;
    }
    coap_subscriber_t subscriber = { .endpoint = ack->endpoint, .cmp = map->endpoint_cmp };
    coap_sub_t needle = { .subscriber = &subscriber, .msg_ID = ack->msg->msg_ID };
    coap_sub_t *key = &needle;
    ZCOAP_LOCK(&map->lock);
    coap_sub_t **sub = map->subidmap ? bsearch(&key, map->subidmap, map->n_subscriptions, sizeof(map->subidmap[0]), &sub_id_cmp) : NULL;
    if (sub != NULL) {
        if (id_in_sub_window(needle.rsp_id, (*sub)->window_left, (*sub)->window_right)) {
            (*sub)->window_left = needle.rsp_id;
        }
    }
    ZCOAP_UNLOCK(&map->lock);
    coap_discard(ack);
}

/**
 * Handle an incoming RESET.  For us, resets are only relevant for tracking
 * observable resources.  If we see a RESET from any endpoints for existing
 * observables, drop the associated subscriptions.
 *
 * @param reset incoming reset request to evaluate
 * @param root URI tree root node
 */
static void
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
coap_handle_reset(coap_req_data_t * const reset, const coap_node_t * const root)
{
    ZCOAP_ASSERT(reset != NULL && root != NULL);
    coap_sub_map_t * const map = root->tsubs;
    ZCOAP_ASSERT(map == NULL || map->endpoint_cmp != NULL);
    if (map == NULL || map->endpoint_cmp == NULL) {
        coap_discard(reset);
        return;
    }
    ZCOAP_LOCK(&map->lock);
    const size_t count = map->n_subscriptions;
    size_t idx = 0;
    for (size_t n = 0; n < count; ++n) {
        coap_sub_t **sub = &map->subtokmap[idx];
        ZCOAP_ASSERT(sub != NULL && (*sub)->subscriber != NULL);
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: examining subscription=%p, subscriber=%p, token=0x%" PRIx64, __func__, *sub, (*sub)->subscriber, (*sub)->token);
        if (map->endpoint_cmp(reset->endpoint, (*sub)->subscriber->endpoint)) {
            ++idx;
            continue;
        }
        ZCOAP_LOG(ZCOAP_LOG_INFO, "%s: reset received, removing subscription=%p, token 0x%" PRIx64 " for subscriber=%p", __func__, (*sub), (*sub)->token, (*sub)->subscriber);
        free_subscription(map, sub);
    }
    ZCOAP_UNLOCK(&map->lock);
    coap_discard(reset);
}

/**
 * Notify a subscriber with the passed code.detail.
 *
 * @param sub subscription for which to publish a code to its observer
 * @return 0 on success, an appropriate CoAP error code on failure
 */
static void
#ifdef __GNUC__
__attribute__((nonnull (1)))
#endif
coap_notify(coap_sub_t *sub, coap_code_t code)
{
    ZCOAP_ASSERT(sub != NULL && sub->tkl <= COAP_MAX_TKL);
    if (window_full(sub->window_left, sub->window_right)) {
        ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: window wrap for subscription with token 0x%" PRIx64 " (left=0x%04X, right=0x%04X); unable to send notification code %u.%02u",
            __func__, sub->token, sub->window_left, sub->window_right, COAP_CODE_TO_CLASS(code), code & COAP_CODE_MASK_DETAIL);
        return;
    }
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: sending code %u.%02u to subscriber with token 0x%" PRIx64, __func__, COAP_CODE_TO_CLASS(code), code & COAP_CODE_MASK_DETAIL, sub->token);
    // Mock an incoming request.  Allocate for message plus maximum sized token.
    union {
        uint8_t opaque[sizeof(coap_msg_t) + COAP_MAX_TKL];
        coap_msg_t typed;
    } sbuf = { 0 };
    coap_msg_t * const req = &sbuf.typed;
    req->tkl = sub->tkl;
    req->type = COAP_TYPE_NON_CONFIRMABLE;
    req->ver = COAP_VERSION;
    req->msg_ID = sub->msg_ID;
    ZCOAP_MEMCPY(COAP_TOKEN(req), &sub->token, sub->tkl);
    coap_req_data_t req_data = { .msg = req };
    req_data.endpoint = sub->subscriber->endpoint;
    req_data.responder = sub->subscriber->responder;
    req_data.context = sub->subscriber->context;
    req_data.len = sizeof(*req) + sub->tkl;
    ++sub->window_right;
    coap_status_rsp(&req_data, code);
}

/**
 * Publish an update to all subscribers observing a node.
 *
 * @param node node for which to publish an update
 */
void coap_publish(coap_node_t * const node)
{
    ZCOAP_ASSERT(node != NULL);
    if (!node->observable) {
        return;
    }
    ZCOAP_ASSERT(node->GET != NULL);
    // Mock an incoming request.  Allocate for message plus maximum sized token.
    #define ZCOAP_PUBLISH_MOCK_REQ_MAXLEN (sizeof(coap_msg_t) + sizeof(((coap_sub_t *)NULL)->token))
    ZCOAP_ASSERT(ZCOAP_PUBLISH_MOCK_REQ_MAXLEN <= ZCOAP_MAX_BUF_SIZE);
    union {
        uint8_t opaque[ZCOAP_PUBLISH_MOCK_REQ_MAXLEN];
        coap_msg_t typed;
    } sbuf = { 0 };
    #undef ZCOAP_PUBLISH_MOCK_REQ_MAXLEN
    coap_msg_t * const req = &sbuf.typed;
    coap_code_t rc = 0;
    ++node->seq;
    coap_req_data_t req_data = { .msg = req, .state = { .obs = true, .seq = node->seq } };
    req->type = COAP_TYPE_NON_CONFIRMABLE;
    req->ver = COAP_VERSION;
    coap_sub_map_t *map = get_sub_map(node);
    ZCOAP_ASSERT(node->singleton && map != NULL);
    ZCOAP_LOCK(&map->lock);
    coap_sub_t *sub = node->nsubs;
    while (sub) {
        if (window_full(sub->window_left, sub->window_right)) {
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: window wrap for subscription with token 0x%" PRIx64 " (left=0x%04X, right=0x%04X)",
                __func__, sub->token, sub->window_left, sub->window_right);
            continue; // window wrap
        }
        ZCOAP_ASSERT(sub->subscriber != NULL);
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: publishing ID 0x%04X for subscription with token 0x%" PRIx64, __func__, sub->msg_ID, sub->token);
        req_data.endpoint = sub->subscriber->endpoint;
        req_data.responder = sub->subscriber->responder;
        req_data.context = sub->subscriber->context;
        req_data.len = sizeof(*req) + sub->tkl;
        req->msg_ID = sub->msg_ID;
        req->tkl = sub->tkl;
        ZCOAP_MEMCPY(COAP_TOKEN(req), &sub->token, sub->tkl);
        (*node->GET)(node, &req_data, 0, NULL, sub->ct, 0, NULL, NULL, NULL);
        ++sub->window_right;
        sub = sub->next;
    }
    ZCOAP_UNLOCK(&map->lock);
}

/**
 * Publish an update for the passed subscription.
 *
 * @param sub subscription for which to publish an update
 * @return 0 on success, an appropriate CoAP error code on failure
 */
static void
#ifdef __GNUC__
__attribute__((nonnull (1)))
#endif
coap_publish_one(coap_sub_t *sub, bool instance)
{
    ZCOAP_ASSERT(   sub != NULL
                 && sub->subscriber != NULL
                 && sub->tkl <= COAP_MAX_TKL
                 && sub->node != NULL
                 && sub->node->GET != NULL);
    if (window_full(sub->window_left, sub->window_right)) {
        ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: window wrap for subscription with token 0x%" PRIx64 " (left=0x%04X, right=0x%04X)",
            __func__, sub->token, sub->window_left, sub->window_right);
        return;
    }
    coap_node_t *node = sub->node;
    if (node->instance != instance) {
        node->instance = instance;
        ++node->seq; // only increment once per node
    }
    // Mock an incoming request.  Allocate for message plus maximum sized token.
    #define ZCOAP_PUBLISH_MOCK_REQ_MAXLEN (sizeof(coap_msg_t) + sizeof(((coap_sub_t *)NULL)->token))
    ZCOAP_ASSERT(ZCOAP_PUBLISH_MOCK_REQ_MAXLEN <= ZCOAP_MAX_BUF_SIZE);
    union {
        uint8_t opaque[ZCOAP_PUBLISH_MOCK_REQ_MAXLEN];
        coap_msg_t typed;
    } sbuf = { 0 };
    #undef ZCOAP_PUBLISH_MOCK_REQ_MAXLEN
    coap_msg_t *req = &sbuf.typed;
    req->ver = COAP_VERSION;
    req->msg_ID = sub->msg_ID;
    req->tkl = sub->tkl;
    ZCOAP_MEMCPY(COAP_TOKEN(req), &sub->token, sub->tkl);
    coap_req_data_t req_data = { .msg = req,
                                 .endpoint = sub->subscriber->endpoint,
                                 .responder = sub->subscriber->responder,
                                 .context = sub->subscriber->context,
                                 .len = sizeof(*req) + sub->tkl,
                                 .state = { .obs = true, .seq = node->seq } };
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: publishing ID 0x%04X for subscription with token 0x%" PRIx64, __func__, sub->msg_ID, sub->token);
    (*node->GET)(node, &req_data, 0, NULL, sub->ct, 0, NULL, NULL, NULL);
    ++sub->window_right;
}

/**
 * Publish an update for all subscriptions.
 *
 * @param map subscription map
 */
void coap_publish_all(coap_sub_map_t * const map)
{
    ZCOAP_ASSERT(map != NULL);
    ZCOAP_LOCK(&map->lock);
    static bool instance = false;
    instance = instance ? false : true;
    for (size_t i = 0; i < map->n_subscriptions; ++i) {
        coap_sub_t *sub = map->subtokmap[i];
        coap_publish_one(sub, instance);
    }
    ZCOAP_UNLOCK(&map->lock);
}

/**
 * Cancel all subscriptions for the passed node and optionally notify subscribers.
 *
 * @param node node for which to cancel subscriptions
 * @param CoAP response code to send to subscribers, or 0 to skip subscriber notification
 */
static void _coap_cancel(coap_node_t * const node, coap_code_t code)
{
    ZCOAP_ASSERT(node != NULL);
    if (!node->observable) {
        return;
    }
    coap_sub_map_t *map = get_sub_map(node);
    ZCOAP_ASSERT(map != NULL);
    ZCOAP_LOCK(&map->lock);
    coap_sub_t *sub;
    while ((sub = node->nsubs)) {
        if (code) {
            coap_notify(sub, code);
        }
        free_subscription(map, &sub);
    }
    ZCOAP_UNLOCK(&map->lock);
}

/**
 * Cancel all subscriptions for the passed node.
 *
 * @param node node for which to cancel subscriptions
 */
void coap_cancel(coap_node_t * const node)
{
    _coap_cancel(node, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_SERVICE_UNAVAIL));
}

/**
 * Cancel all subscriptions in the passed map.
 *
 * @param map subscription map
 */
void coap_cancel_all(coap_sub_map_t * const map)
{
    ZCOAP_LOCK(&map->lock);
    const size_t count = map->n_subscriptions;
    size_t idx = 0;
    for (size_t n = 0; n < count; ++n) {
        coap_sub_t **sub = &map->subtokmap[idx];
        ZCOAP_LOG(ZCOAP_LOG_INFO, "%s: canceling subscription=%p, token 0x%" PRIx64 " for subscriber=%p", __func__, (*sub), (*sub)->token, (*sub)->subscriber);
        coap_notify(*sub, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_SERVICE_UNAVAIL));
        free_subscription(map, sub);
    }
    ZCOAP_UNLOCK(&map->lock);
}

/**
 * Iterate through all subscriptions and free those for which the outstanding
 * ACK window size implies the subscriber has disappeared.
 *
 * @param map subscription map
 */
void coap_garbage_collect(coap_sub_map_t* const map)
{
    ZCOAP_LOCK(&map->lock);
    const size_t count = map->n_subscriptions;
    size_t idx = 0;
    for (size_t n = 0; n < count; ++n) {
        coap_sub_t **sub = &map->subtokmap[idx];
        coap_msg_id_t window = sub_window((*sub)->window_left, (*sub)->window_right);
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: examining subscription=%p, subscriber=%p, token=0x%" PRIx64 " with window size %u", __func__, *sub, (*sub)->subscriber, (*sub)->token, window);
        ZCOAP_ASSERT(ZCOAP_SUB_DROP_THRESH < ((1 << ZCOAP_SUB_NSTART_BITS) - 1));
        if (window < ZCOAP_SUB_DROP_THRESH) {
            ++idx;
            continue;
        }
        ZCOAP_LOG(ZCOAP_LOG_INFO, "%s: garbage collecting stale subscription=%p, token 0x%" PRIx64 "for subscriber=%p", __func__, (*sub), (*sub)->token, (*sub)->subscriber);
        coap_notify(*sub, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_SERVICE_UNAVAIL));
        free_subscription(map, sub);
    }
    ZCOAP_UNLOCK(&map->lock);
}

/**
 * Evaluate whether the passed request / response pair should trigger publishing
 * an update to subscribers.  Updates should be published for PUT/POST
 * modification requests that have elicited a 2.XX-class success response.  If
 * an update should be published, return the associated node.  Else, return NULL.
 *
 * @param req initiating request to inspect
 * @param rsp request response to inspect
 * @return node for which to publish an update, else NULL
 */
static coap_node_t *auto_publish(coap_req_data_t * const req, const coap_msg_t * const rsp)
{
    ZCOAP_ASSERT(req != NULL && req->msg != NULL && req->msg->code.code_class == COAP_REQ);
    if (req->state.node == NULL) {
        return NULL; // Non-singleton nodes are not enclosed and cannot be subscibed.
    }
    switch (req->msg->code.code_detail) {
        case COAP_REQ_METHOD_PUT:
        case COAP_REQ_METHOD_POST:
            if (rsp->code.code_class == COAP_SUCCESS) {
                return req->state.node;
            }
            break;
        default:
            break;
    }
    return NULL;
}

/*********** End RFC7641 observation request utility functions. ************/

/**
 * Issue a CoAP response to req and enclosing the passed data.
 * Calls req->discard regardless of outcome.
 *
 * @param req CoAP request to which to respond
 * @param code CoAP response code
 * @param nopts number of response message options
 * @param opts response message options
 * @param pl_len response payload length
 * @param payload response payload
 */
void coap_rsp(coap_req_data_t * const req, coap_code_t code, size_t nopts, const coap_opt_t opts[], size_t pl_len, const void * const payload)
{
    // Check arguments.
    ZCOAP_ASSERT(   req != NULL
                 && req->msg != NULL
                 && req->len >= sizeof(coap_msg_t)
                 && req->len >= sizeof(coap_msg_t) + req->msg->tkl
                 && req->msg->tkl <= COAP_MAX_TKL
                 && req->responder != NULL
                 && (pl_len == 0 || payload != NULL));
    // Apppend observe option if appropriate.
    coap_obs_seq_t seq;
#ifdef __GNUC__
    // Allocate a temp pointer array on the stack.  This is for an outgoing
    // message, not an incoming message.  Thus we are not concerned about
    // a client injecting data that will lead to our stack overflow - we are
    // in full control of this message and are confident the options array
    // is of reasonable size.  Thus we do not bounds check.
    coap_opt_t lopts[nopts + 1];
#else
    // Non-C99 platforms don't permit a variable-length array.  So we must
    // choose some reasonable limit and statically allocate.
    if (nopts + 1 > ZCOAP_MAX_PAYLOAD_OPTS) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    const coap_opt_t lopts[ZCOAP_MAX_PAYLOAD_OPTS];
#endif /* __GNUC__ */
    if (req->state.obs) {
        seq = req->state.seq;
        build_observe_option(&seq, &lopts[nopts]);
        ZCOAP_MEMCPY(lopts, opts, sizeof(opts[0]) * nopts);
        opts = lopts;
        ++nopts;
    }
    // Determine how big our response PDU will be.
    size_t alen;
    ZCOAP_ASSERT(compute_rsp_pdu_len(req, nopts, opts, pl_len, &alen) == 0);
    // Allocate our response PDU.  Keep it on the stack if we can.
    coap_msg_t *rsp;
    union {
        uint8_t opaque[ZCOAP_MAX_BUF_SIZE];
        coap_msg_t typed;
    } sbuf;
    if (alen <= sizeof(sbuf)) {
        rsp = &sbuf.typed;
    } else if ((rsp = ZCOAP_ALLOCA(alen)) == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    uint8_t *pl_ptr;
    ZCOAP_ASSERT((pl_ptr = populate_rsp_header(req, code, nopts, opts, rsp)) != NULL);
    if (pl_len && payload) {
        *pl_ptr = COAP_PAYLOAD_MARKER;
        ++pl_ptr;
        ZCOAP_MEMCPY(pl_ptr, payload, pl_len);
    }
    // Transmit the response!
    (*req->responder)(req, alen, rsp);
    // Determine whether we need to publish subscription updates.
    coap_node_t * const subscribed_node = auto_publish(req, rsp);
    // Free req and rsp.
    if (rsp && alen > ZCOAP_MAX_BUF_SIZE) {
        ZCOAP_ALLOCA_FREE(rsp);
    }
    coap_discard(req);
    // Finally, publish subscription updates.
    // We do this after freeing req/resp to minimize memory footrpint.
    if (subscribed_node) {
        coap_publish(subscribed_node);
    }
}

/**
 * Issue a CoAP response with the CoAP response code specified and enclosing
 * the passed payload.
 *
 * @param req CoAP request to which to respond
 * @param code CoAP response code
 * @param ct CoAP content format type designator
 * @param pl_len payload length
 * @param payload payload
 */
void coap_content_rsp(coap_req_data_t* const req, const coap_code_t code, coap_ct_t ct, const size_t pl_len, const void* const payload)
{
    coap_opt_t opts[] = {
        { .num = COAP_OPT_CONTENT_FMT },
    };
    uint8_t ct_lsb;
    if (ct <= 0xFF) {
        // If ct can fit in a byte on the wire, pack it accordingly.
        // We need to properly grab the LSB though.
        ct_lsb = ct;
        opts->val = &ct_lsb;
        opts->len = sizeof(ct_lsb);
    } else {
        // Nope, we need two bytes.  Convert to big-endian though
        // for the wire.
        ct = ZCOAP_HTONS(ct);
        opts->val = &ct;
        opts->len = sizeof(ct);
    }
    coap_rsp(req, code, NELM(opts), opts, pl_len, payload);
}

/**
 * Issue a CoAP response with the CoAP response code specified and enclosing the
 * passed detail string in the payload.
 *
 * @param req CoAP request to which to respond
 * @param code CoAP response code
 * @param detail
 * @return 0 on success, non-zero on error
 */
void coap_detail_rsp(coap_req_data_t* const req, const coap_code_t code, const char* const detail)
{
    coap_content_rsp(req, code, COAP_FMT_TEXT, strlen(detail), detail);
}

/**
 * Issue a CoAP response with the CoAP response code specified.
 *
 * @param req CoAP request to which to respond
 * @param code CoAP response code
 * @return 0 on success, non-zero on error
 */
void coap_status_rsp(coap_req_data_t* const req, const coap_code_t code)
{
    /*
     * We must be able to fit simple error status responses in a stack buffer.
     * This is to guarantee we are not silent for allocation failures.
     */
    ZCOAP_ASSERT(ZCOAP_MAX_BUF_SIZE >= sizeof(coap_msg_t) + COAP_MAX_TKL);
    coap_rsp(req, code, 0, NULL, 0, NULL);
}

/**
 * GET request handler for .well-known/core.  Perform a depth-first search of
 * the CoAP URI tree and print all URIs as prescribed by RFC-6690.
 *
 * Finds the root node '/' by relative reference from ./core, i.e.:
 *    /.well-known/core/../../
 *
 * Note that this function does not call into coap_rsp.  Were we to do so, we
 * would be forced to allocate here and then allocate again up the stack in
 * coap_rsp.  This could be quite expensive, as /.well-known/core is likely one
 * of our larger resources.  So instead, we execute all coap response logic
 * here in immediate context.
 *
 * @param req initiating CoAP request
 * @param nopts number of request options
 * @param opts request options
 * @param node pointer to .well-known/core tree node
 * @param ctmask (in/out) if non-null, passed to ZCOAP_METHOD_HEADER macro to set appropriate content type bits
 */
static void coap_get_wellknown_core(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_LINK, ZCOAP_FMT_SENTINEL);
    ZCOAP_ASSERT(req != NULL && req->responder != NULL);
    const uint8_t ct_fmt_link = COAP_FMT_LINK;
    const coap_opt_t rsp_opts[] = {
        { .num = COAP_OPT_CONTENT_FMT, .val = &ct_fmt_link },
    };
    if (node == NULL || node->parent == NULL || node->parent->parent == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    coap_node_t root = *node->parent->parent; // locate root at /.well-known/core/../../
    const href_filter_t href_filter = get_href_filter(nopts, opts);
    size_t wkn_len = snprintf_wellknown_core(NULL, 0, root, &href_filter);
    size_t pdu_len;
    ZCOAP_ASSERT(compute_rsp_pdu_len(req, NELM(rsp_opts), rsp_opts, wkn_len, &pdu_len) == 0);
    coap_msg_t *rsp = ZCOAP_ALLOCA(pdu_len + 1 /* \0 */);
    if (rsp == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    uint8_t *pl_ptr = populate_rsp_header(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), NELM(rsp_opts), rsp_opts, rsp);
    if (pl_ptr == NULL) {
        ZCOAP_ALLOCA_FREE(rsp);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    if (wkn_len) {
        *pl_ptr = COAP_PAYLOAD_MARKER;
        ++pl_ptr;
        size_t _wkn_len = snprintf_wellknown_core((char *)pl_ptr, wkn_len + 1, root, &href_filter);
        if (_wkn_len > wkn_len) {
            // oops, wellknown-core changed and is now truncated
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: dynamic tree elements changed while generating .well-known/core", __func__);
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
            return;
        }
        size_t delta = wkn_len - _wkn_len;
        pdu_len -= delta;
        wkn_len -= delta;
        if (wkn_len) {
            if (pl_ptr[wkn_len - 1] == ',') {
                --wkn_len;
                --pdu_len;
            }
        }
        if (!wkn_len) {
            --pdu_len;
        }
    } else {
    }

    // Transmit the response!
    (*req->responder)(req, pdu_len, rsp);
    // Free our memory and cleanup.
    ZCOAP_ALLOCA_FREE(rsp);
    coap_discard(req);
}
static coap_node_t core_uri = { .name = "core", .GET = &coap_get_wellknown_core };
static coap_node_t *wellknown_children[] = { &core_uri, NULL };

/**
 * wellknown_uri
 *
 * Implementations should place the wellknown URI as an immediate child of each
 * server's URI tree root node.  This provides each referencing tree with a
 * /.well-known/core URI with GET handler that can dynamically produce a tree
 * diagram for dynamic resource discovery from the client side.
 *
 * As can be seen in the handler's implementation above, this is actually
 * pretty complex!  But it's all pretty well-structured.  We're performing a
 * depth-first search using the C stack; cool!  Also worth noting: the ZCoAP
 * server is one of the *very* few (actually, the only one this writer knows
 * of) that provides content-type discovery in the .well-known/core interface.
 * Big value!
 */
coap_node_t wellknown_uri = { .name = ".well-known", .children = wellknown_children };

/**
 * Iterator function to find the next option in a CoAP message.
 *
 * @param buf (in/out) pointer to current location in a CoAP message; advanced past the parsed option
 * @param remain (in/out) remaining bytes in the message; advanced past the parsed option
 * @param num (out) parsed option  number
 * @param len (out) parsed option length
 * @param val (out) parsed option value
 * @return 0 on success, else a CoAP error code
 */
static coap_code_t opt_next(const uint8_t **buf, size_t * const remain, uint32_t * const num, uint16_t * const len, const void **val)
{
    if (!*remain) {
        return 0;
    }
    if (**buf == COAP_PAYLOAD_MARKER) {
        *remain = 0;
        ++*buf;
        return 0;
    }
    size_t opd_ex_bytes = 0;
    uint16_t option_delta = (**buf >> 4) & 0xF;
    switch (option_delta) {
        case 13:
            if (*remain < 2) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
            }
            option_delta = *(*buf + 1) + 13;
            opd_ex_bytes = 1;
            break;
        case 14:
            if (*remain < 3) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
            }
            {
                uint16_t net;
                ZCOAP_MEMCPY(&net, *buf + 1, sizeof(net));
                option_delta = ZCOAP_NTOHS(net) + 269;
            }
            opd_ex_bytes = 2;
            break;
        case 15:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
        default:
            break;
    }
    *num += option_delta;
    size_t opl_ex_bytes = 0;
    *len = **buf & 0xF;
    switch (*len) {
        case 13:
            if (*remain < 2 + opd_ex_bytes) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
            }
            *len = *(*buf + 1 + opd_ex_bytes) + 13;
            opl_ex_bytes = 1;
            break;
        case 14:
            if (*remain < 3 + opd_ex_bytes) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
            }
            {
                uint16_t net;
                ZCOAP_MEMCPY(&net, *buf + 1 + opd_ex_bytes, sizeof(net));
                *len = ZCOAP_NTOHS(net) + 269;
            }
            opl_ex_bytes = 2;
            break;
        case 15:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
        default:
            break;
    }
    size_t offset_to_val = 1 + opd_ex_bytes + opl_ex_bytes;
    *buf += offset_to_val;
    *remain -= offset_to_val;
    if (*remain < *len) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
    }
    *val = *buf;
    *buf += *len;
    *remain -= *len;
    return 0;
}

/**
 * Count the options in a CoAP request.
 *
 * @param req CoAP request for which to count options.
 * @param nopts (out) number of options found in the request
 * @return 0 on success, else a CoAP error code
 */
static coap_code_t
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
coap_count_opts(coap_req_data_t* const req, size_t* const nopts)
{
    ZCOAP_ASSERT(req != NULL && req->msg != NULL && nopts != NULL);
    if (req->len < sizeof(coap_msg_t)) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    if (req->msg->tkl > COAP_MAX_TKL) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    size_t remain = req->len - sizeof(coap_msg_t);
    if (remain < req->msg->tkl) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    remain -= req->msg->tkl;
    const uint8_t *ptr = COAP_OPTS(req->msg);
    uint32_t opt_num = 0;
    *nopts = 0;
    while (remain && *ptr != COAP_PAYLOAD_MARKER) {
        uint16_t opt_len; // discard
        const void *opt_val; // discard
        coap_code_t rc;
        if ((rc = opt_next(&ptr, &remain, &opt_num, &opt_len, &opt_val))) {
            return rc;
        }
        ++*nopts;
    }
    return 0;
}

/**
 * Parse the options from the passed request.
 *
 * @param req CoAP request from which to parse options
 * @param nopts maximum number of options to parse
 * @param opts (out) write location for parsed options
 * @return 0 on success, else a CoAP error code
 */
static coap_code_t
#ifdef __GNUC__
__attribute__((nonnull (1, 3)))
#endif
coap_get_opts(coap_req_data_t* const req, const size_t nopts, coap_msg_opt_t* const opts)
{
    ZCOAP_ASSERT(req != NULL && req->msg != NULL && opts != NULL);
    if (req->len < sizeof(coap_msg_t)) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    if (req->msg->tkl > COAP_MAX_TKL) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    size_t remain = req->len - sizeof(coap_msg_t);
    if (remain < req->msg->tkl) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    remain -= req->msg->tkl;
    const uint8_t *ptr = COAP_OPTS(req->msg);
    uint32_t opt_num = 0;
    for (size_t i = 0; i < nopts; ++i) {
        if (!remain || *ptr == COAP_PAYLOAD_MARKER) {
            ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: options parse error", __func__);
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
        coap_code_t rc;
        if ((rc = opt_next(&ptr, &remain, &opt_num, &opts[i].len, &opts[i].val))) {
            return rc;
        }
        opts[i].num = opt_num;
    }
    return 0;
}

/**
 * Get a CoAP content type designator from a content format or accept option
 * in a CoAP request.  Parses req for its options if caller passes opts == NULL.
 *
 * @param req request to search for content format option
 * @param nopts number of options in the request
 * @param opts parsed request options, or null if not available
 * @param needle option number to search for; must be  COAP_OPT_CONTENT_FMT or COAP_OPT_ACCEPT
 * @param ct (out) content type designator from the caller-specified option, or ZCOAP_FMT_NONE if the option was not found
 * @return 0 on success, else CoAP error code; note that content format option not found is NOT an error; in such a case, content_fmt remains unwritten
 */
static coap_code_t coap_get_content_type_designator(coap_req_data_t* const req, size_t nopts, const coap_msg_opt_t opts[], coap_opt_num_t needle, coap_ct_t* const ct)
{
    if (needle != COAP_OPT_CONTENT_FMT && needle != COAP_OPT_ACCEPT) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (ct == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (opts == NULL && req == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    *ct = ZCOAP_FMT_NONE;
    coap_code_t rc;
    if (opts == NULL && (rc = coap_count_opts(req, &nopts))) {
        return rc;
    }
    if (nopts == 0) {
        *ct = ZCOAP_FMT_NONE;
        return 0;
    }
    coap_msg_opt_t ct_opt = { 0 };
    // In the bsearch, we will find *an* occurrence of a content-format option.
    // If the requesting agent has enclosed more than one, that's a protocol
    // violation on their part and not our problem.
    if (opts == NULL) {
        if (nopts > ZCOAP_MAX_PAYLOAD_OPTS) {
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: too many options", __func__);
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
#ifdef __GNUC__
        coap_msg_opt_t lopts[nopts]; // allocate temp pointer array on the stack
#else
        coap_msg_opt_t lopts[ZCOAP_MAX_PAYLOAD_OPTS];
#endif /* __GNUC__ */
        if ((rc = coap_get_opts(req, nopts, lopts))) {
            return rc;
        }
        const coap_msg_opt_t key = { .num = needle };
        coap_msg_opt_t *_ct_opt = bsearch(&key, lopts, nopts, sizeof(lopts[0]), &opt_cmp);
        if (_ct_opt == NULL) {
            *ct = ZCOAP_FMT_NONE;
            return 0;
        }
        ct_opt = *_ct_opt;
    } else {
        const coap_msg_opt_t key = { .num = needle };
        coap_msg_opt_t *_ct_opt = bsearch(&key, opts, nopts, sizeof(opts[0]), &opt_cmp);
        if (_ct_opt == NULL) {
            *ct = ZCOAP_FMT_NONE;
            return 0;
        }
        ct_opt = *_ct_opt;
    }
    if (!ct_opt.len) {
        // Per RFC 7252, a zero-length option value field is simply
        // empty.  And this is legal for the content format
        // designator.  We'll interpret this as unspecified / don't
        // care.  To the caller, this will be equivalent to the case
        // where no content format option was included at all.
        return 0;
    }
    if (ct_opt.len > sizeof(coap_ct_t)) {
        // Per RFC6690, content format option value should be 65535 or less.
        // We will therefore only accept 0, 1 and 2-byte value fields.  We
        // suppose a client could pack a 2-byte big-endian content type into
        // *more* bytes, but this seems an odd abuse of the wire format.
        // Reject!
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
    } else if (ct_opt.len == sizeof(coap_ct_t)) {
        uint16_t netshort;
        ZCOAP_MEMCPY(&netshort, ct_opt.val, sizeof(netshort));
        *ct = ZCOAP_NTOHS(netshort);
    } else {
        *ct = *(uint8_t *)ct_opt.val;
    }
    return 0;
}

/**
 * Get a CoAP content type designator from a content format option in a CoAP request.
 * Parses req for its options if caller passes opts == NULL.
 *
 * @param req request to search for content format option
 * @param nopts number of options in the request
 * @param opts parsed request options, or null if not available
 * @param ct (out) content type designator from the enclosed content format option, or ZCOAP_FMT_NONE if the no content format option was found
 * @return 0 on success, else CoAP error code; note that content format option not found is NOT an error; in such a case, content_fmt remains unwritten
 */
coap_code_t coap_get_content_type(coap_req_data_t* const req, size_t nopts, const coap_msg_opt_t opts[], coap_ct_t* const ct)
{
   return coap_get_content_type_designator(req, nopts, opts, COAP_OPT_CONTENT_FMT, ct);
}

/**
 * Get a CoAP content type designator from an accept option in a CoAP request.
 * Parses req for its options if caller passes opts == NULL.
 *
 * @param req request to search for content format option
 * @param nopts number of options in the request
 * @param opts parsed request options, or null if not available
 * @param ct (out) content type designator from the enclosed accept option, or ZCOAP_FMT_NONE if the no accept option was found
 * @return 0 on success, else CoAP error code; note that content format option not found is NOT an error; in such a case, content_fmt remains unwritten
 */
coap_code_t coap_get_accept_type(coap_req_data_t* const req, size_t nopts, const coap_msg_opt_t opts[], coap_ct_t* const ct)
{
   return coap_get_content_type_designator(req, nopts, opts, COAP_OPT_ACCEPT, ct);
}

/**
 * Get the payload from the passed request.
 *
 * @param req CoAP request to parse
 * @param len (out) payload length
 * @param payload (out) payload
 * @return 0 on success, else CoAP error code
 */
coap_code_t coap_get_payload(coap_req_data_t* const req, size_t* const len, const void** payload)
{
    if (req == NULL || len == NULL || payload == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (req->len < sizeof(coap_msg_t)) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    if (req->msg->tkl > COAP_MAX_TKL) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    size_t remain = req->len - sizeof(coap_msg_t);
    if (remain < req->msg->tkl) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    remain -= req->msg->tkl;
    uint8_t *ptr = COAP_OPTS(req->msg);
    *len = 0;
    while (remain) {
        if (*ptr == COAP_PAYLOAD_MARKER) {
            *len = remain - 1;
            *payload = ptr + 1;
            break;
        }
        ++ptr;
        --remain;
    }
    return 0;
}

/**
 * Extract content type and payload from the passed request.  If an error
 * occurs, return an appropriate CoAP error code from the calling context.
 *
 * @param req CoAP request for which to extract content type and payload
 */
#define EXTRACT_CONTENT_TYPE_AND_PAYLOAD(_req) {\
    coap_code_t _rc;\
    if ((_rc = coap_get_content_type(_req, nopts, opts, &ct))) {\
        return _rc;\
    }\
    if ((_rc = coap_get_payload(_req, &len, &payload))) {\
        return _rc;\
    }\
}

/**
 * Process a CoAP request and dispatch to the appropriate handler based upon
 * message class and request method.  On success, return code 2.00, a CoAP
 * 'success-class' response code.  On error, return an appropriate error
 * code.  On success, the handler becomes responseible for responding to the
 * client and calling discard.
 *
 * @param req CoAP request to process
 * @param nopts number of options in the request
 * @param opts parsed request options, or NULL if unavailable to the caller
 * @param node server tree node matching request URI
 * @param subs subscription map
 * @return 0 on success, else a CoAP error code
 */
static coap_code_t
#ifdef __GNUC__
__attribute__((nonnull (1, 4)))
#endif
process_req_uri(coap_req_data_t* const req, const size_t nopts, const coap_msg_opt_t opts[], coap_node_t* const node)
{
    ZCOAP_ASSERT(req != NULL && req->msg != NULL && node != NULL);
    req->state.node = node->singleton ? node : NULL;
    coap_ct_t ct;
    size_t len;
    const void *payload;
    EXTRACT_CONTENT_TYPE_AND_PAYLOAD(req);
    coap_code_t rc;
    if ((rc = process_observe_req(node, req, nopts, opts, ct))) {
        return rc;
    }

    // On successful handler dispatch, return CoAP succes, 2.00.  In such a
    // case, the handler becomes responsible for responding to the client and
    // calling discard.
    //
    // On failure, return an appropriate error code.
    coap_lock(node);
    switch (req->msg->code.code_class) {
        case COAP_REQ:
            switch (req->msg->code.code_detail) {
                case COAP_REQ_METHOD_GET:
                    if (node->GET) {
                        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: servicing GET for path '%s'", __func__, node->name);
                        (*node->GET)(node, req, nopts, opts, ct, len, payload, NULL, NULL);
                        rc = COAP_CODE(COAP_SUCCESS, 0);
                    } else {
                        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: GET method unsupported for path '%s'", __func__, node->name);
                        rc = COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED);
                    }
		    break;
                case COAP_REQ_METHOD_PUT:
                    if (node->PUT) {
                        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: servicing PUT for path '%s'", __func__, node->name);
                        (*node->PUT)(node, req, nopts, opts, ct, len, payload, NULL, NULL);
                        rc = COAP_CODE(COAP_SUCCESS, 0);
                    } else {
                        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: PUT method unsupported for path '%s'", __func__, node->name);
                        rc = COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED);
                    }
		    break;
                case COAP_REQ_METHOD_POST:
                    if (node->POST) {
                        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: servicing POST for path '%s'", __func__, node->name);
                        (*node->POST)(node, req, nopts, opts, ct, len, payload, NULL, NULL);
                        rc = COAP_CODE(COAP_SUCCESS, 0);
                    } else {
                        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: POST method unsupported for path '%s'", __func__, node->name);
                        rc = COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED);
                    }
		    break;
                case COAP_REQ_METHOD_DEL:
                    if (node->DEL) {
                        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: servicing DEL for path '%s'", __func__, node->name);
                        (*node->DEL)(node, req, nopts, opts, ct, len, payload, NULL, NULL);
                        rc = COAP_CODE(COAP_SUCCESS, 0);
                    } else {
                        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: DEL method unsupported for path '%s'", __func__, node->name);
                        rc = COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED);
                    }
		    break;
                default:
                    ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: unable to service method %u for path '%s'", __func__, req->msg->code.code_detail, node->name);
                    rc = COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED);
		    break;
            }
        default:
            ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: unexpectedly passed message with class %u, path option '%s'", __func__, req->msg->code.code_class, node->name);
            rc = COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
	    break;
    }
    coap_unlock(node);
    return rc;
}

/**
 * Perform a node name comparison for p and q.  Used to qsort the tree at init
 * and used for fast URI match with bsearch at runtime.
 *
 * @param p node to compare
 * @param q node to compare
 * @return 1 if p>q, 0 if p==q, -1 if p<q
 */
static int coap_node_cmp(const void * const p, const void * const q)
{
    const coap_node_t *a = *(const coap_node_t **)p;
    const coap_node_t *b = *(const coap_node_t **)q;
    if (a->name == b->name) {
        return 0;
    } else if (b->name == NULL) {
        return -1;
    } else if (a->name == NULL) {
        return 1;
    } else {
        return strcmp(a->name, b->name);
    }
}

/**
 * UrI tree children are stored in null-terminated arrays.  Count the passed
 * node's children.
 *
 * @param node URI tree node for which to count children
 * @return number of children found
 */
static size_t coap_count_children(const coap_node_t * const node)
{
    size_t count = 0;
    coap_node_t **child = node->children;
    while (child && *child) {
        ++count;
        ++child;
    }
    return count;
}

static coap_code_t iter_req(coap_node_t* const node, const void* data);

/**
 * Data interface for iter_req.
 *
 * @param req CoAP request to handle
 * @param nopts number of options enclosed in req
 * @param opts array of option pointers into req
 * @param npath_opts number of path options enclosed in req
 * @param path_opts array of path option pointers into req
 */
typedef struct iter_req_data_s {
    coap_req_data_t * const req;
    const size_t nopts;
    const coap_msg_opt_t *opts;
    size_t npath_opts;
    const coap_msg_opt_t *path_opts;
} iter_req_data_t;


/**
 * Wrapped CoAP request iterator that always presumes match between node->name
 * and the immediately previous path_opt.  Can be called against root node
 * which is always a match.
 *
 * @param node current tree node for our depth-first tree walk
 * @param data iter_req_data_t
 * @return 0.00 if caller should keep iterating, non-zero if not; inject_coap_req will issue coap_status_rsp for non-2.00-class success codes
 */
static coap_code_t
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
_iter_req(coap_node_t * const node, const void * data)
{
    ZCOAP_ASSERT(node != NULL && data != NULL);
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: depth-first search at path segment '%s'", __func__, node->name);
    const iter_req_data_t *cdata = (const iter_req_data_t *)data;
    if (!cdata->npath_opts) { // Ding ding!  No more path options!  Match!
        return process_req_uri(cdata->req, cdata->nopts, cdata->opts, node);
    }
    const size_t count = coap_count_children(node);
    const coap_msg_opt_t *opt = &cdata->path_opts[0];
    // We bounds check for ZCOAP_MAX_BUF_SIZE and skip path segments that are
    // too large.  We can't allow clients to inject data that will grow our
    // stack unreasonably.
    if (count && opt->len < ZCOAP_MAX_BUF_SIZE) {
#ifdef __GNUC__
        char keyname[opt->len + 1];
#else
        char keyname[ZCOAP_MAX_BUF_SIZE];
#endif /* __GNUC__ */

        ZCOAP_MEMCPY(keyname, opt->val, opt->len);
        keyname[opt->len] = '\0';
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: searching for child '%s'", __func__, keyname);
        coap_node_t needle = { .name = keyname };
        coap_node_t *key = &needle;
        coap_node_t * const * const c = bsearch(&key, node->children, count, sizeof(node->children[0]), coap_node_cmp);
        if (c) {
            // Here, we pass the child itself by reference, not a copy.
            // We require access to the child node in order to store back
            // observer subscriptions.
            coap_node_t *child = *c;
            child->parent = node;
            child->singleton = node->singleton; // singleton is inherited
            return iter_req(child, cdata);
        }
    }
    if (node->gen) {
        coap_code_t code = (*node->gen)(node, &iter_req, cdata);
        if (code) {
            return code;
        }
    }
    if (node->wildcard) { // if no children matched, but the parent has wildcard set, recurse into the wildcard function
        const coap_msg_opt_t *opt = &cdata->path_opts[0];
        // We bounds check for ZCOAP_MAX_BUF_SIZE and skip path segments that are
        // too large.  We can't allow clients to inject data that will grow our
        // stack unreasonably.
        if (opt->len < ZCOAP_MAX_BUF_SIZE) {

#ifdef __GNUC__
            char child[opt->len + 1];
#else
            char child[ZCOAP_MAX_BUF_SIZE];
#endif /* __GNUC__ */

            ZCOAP_MEMCPY(child, opt->val, opt->len);
            child[opt->len] = '\0';
            coap_code_t code = (*node->wildcard)(node, child, &iter_req, cdata);
            if (code) {
                return code;
            }
        }
    }
    {
        // CoAP path options are text, but are not terminated with '\0'.
        // Copy to a stack buffer and NULL-terminate.
        size_t debug_str_len = opt->len < ZCOAP_MAX_BUF_SIZE ? opt->len : ZCOAP_MAX_BUF_SIZE - 1;
#ifdef __GNUC__
        char buf[debug_str_len + 1];
#else
        char buf[ZCOAP_MAX_BUF_SIZE];
#endif /* __GNUC__ */

        ZCOAP_MEMCPY(buf, opt->val, debug_str_len);
        buf[debug_str_len] = '\0';
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: unable to resolve request path '%s'!", __func__, buf);
    }
    // If we ever get here, it means the client specified a path
    // segment that we were unable to resolve.  Hence, 404.
    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NOT_FOUND);
}

/**
 * CoAP request iterator:
 *
 *   * Compare node->name to the current path option.
 *   * On miss, return 0.
 *   * Else, on last path option, we match!  Dispatch to the server and return!
 *   * Else,  bsearch for a child match.
 *   * On child-match, recurse to the child and return.
 *   * Else, if there is a dynamic-child-node generator, recuse to the generator.
 *   * Else return 4.04, not found.
 *
 * Return codes should be interpreted as follows:
 *
 *   * 0.00: no match and no error - caller should keep iterating
 *   * 2.00: match and successful dispatch - caller should cease iterating
 *   * 4.XX or 5.XX: error - caller should cease iterating and return the error to the top level
 *
 * At the top level, 4.XX and 5.XX codes should evoke a corresponding client response.
 *
 * @param node current tree node for our depth-first tree walk
 * @param data iter_req_data_t
 * @return 0.00 if caller should keep iterating, non-zero if not; inject_coap_req will issue coap_status_rsp for non-2.00-class success codes
 */
static coap_code_t iter_req(coap_node_t* const node, const void* data)
{
    if (node == NULL || data == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    const iter_req_data_t *pdata = (const iter_req_data_t *)data;
    if (pdata->path_opts == NULL || pdata->path_opts->val == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (   !pdata->npath_opts
        || !node->name /* impossible for null-name to be a match */
        || strncmp(pdata->path_opts->val, node->name, pdata->path_opts->len)
        || strlen(node->name) != pdata->path_opts->len) {
        return 0;
    }
    const iter_req_data_t cdata = {
        .req = pdata->req,
        .nopts = pdata->nopts,
        .opts = pdata->opts,
        .npath_opts = pdata->npath_opts - 1,
        .path_opts = pdata->path_opts + 1,
    };
    return _iter_req(node, &cdata);
}

/**
 * Inject a CoAP request into our CoAP server and process it through the URI
 * tree starting at the passed root node.
 *
 * @param req CoAP request to inject into the server
 * @param root root of the URI tree that should be used to process the request
 */
static void
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
inject_coap_req(coap_req_data_t* const req, coap_node_t* const root)
{
    ZCOAP_ASSERT(req != NULL && root != NULL);
    size_t nopts;
    size_t npath_opts = 0;
    coap_msg_opt_t *first_path_opt = NULL;
    coap_code_t rc;
    // Count options.
    if ((rc = coap_count_opts(req, &nopts))) {
        coap_status_rsp(req, rc);
        return;
    }
    // Parse options array.
    if (nopts > ZCOAP_MAX_PAYLOAD_OPTS) {
        ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: too many options", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
#ifdef __GNUC__
    coap_msg_opt_t opts[nopts];
#else
    coap_msg_opt_t opts[ZCOAP_MAX_PAYLOAD_OPTS];
#endif /* __GNUC__ */

    if ((rc = coap_get_opts(req, nopts, opts))) {
        coap_status_rsp(req, rc);
        return;
    }
    // Search for any occurrences of proxy options.
    // We do not support forward-proxy operation.
    {
        const coap_msg_opt_t key = { .num = COAP_OPT_PROXY_URI };
        const coap_msg_opt_t * const proxy_uri_opt = bsearch(&key, opts, nopts, sizeof(opts[0]), &opt_cmp);
        if (proxy_uri_opt != NULL) {
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_NO_PROXY_SUPPORT));
            return;
        }
    }
    {
        const coap_msg_opt_t key = { .num = COAP_OPT_PROXY_SCHEME };
        const coap_msg_opt_t * const proxy_scheme_opt = bsearch(&key, opts, nopts, sizeof(opts[0]), &opt_cmp);
        if (proxy_scheme_opt != NULL) {
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_NO_PROXY_SUPPORT));
            return;
        }
    }
    // Parse for path options.
    while (nopts) {
        // Find *an* occurrence of a path option (perhaps not the first).
        const coap_msg_opt_t key = { .num = COAP_OPT_PATH };
        coap_msg_opt_t *a_path_opt = bsearch(&key, opts, nopts, sizeof(opts[0]), &opt_cmp);
        if (a_path_opt == NULL) {
            break; // no path options
        }
        // Now find the *first* occurrence of a path option.
        for (coap_msg_opt_t *opt = a_path_opt; ; --opt) {
            if (opt->num != COAP_OPT_PATH) {
                first_path_opt = opt + 1;
                break;
            }
            if (opt == opts) {
                first_path_opt = opt;
                break;
            }
        }
        coap_msg_opt_t *end = opts + nopts;
        npath_opts = 0;
        for (coap_msg_opt_t *opt = first_path_opt; opt < end && opt->num == COAP_OPT_PATH; ++opt) {
            ++npath_opts;
        }
        break;
    }
    // Dispatch.
    {
        const iter_req_data_t iter_data = {
            .req = req,
            .nopts = nopts,
            .opts = nopts ? opts : NULL,
            .npath_opts = npath_opts,
            .path_opts = first_path_opt,
        };
        rc = _iter_req(root, &iter_data);
        if (rc && COAP_CODE_TO_CLASS(rc) != COAP_SUCCESS) {
            coap_status_rsp(req, rc);
        }
    }
}

/**
 * CoAP server entry point.  Parse incoming CoAP messages and, if apporpiate,
 * inject into the server for handling with the URI tree anchored at the passed
 * root node.
 *
 * @param req transport-agnostic CoAP message structure
 * @param root root node of tree to be used for handling incoming requests
 * @param subs subscription map
 */
void coap_rx(coap_req_data_t * const req, coap_node_t root)
{
    ZCOAP_ASSERT(req != NULL);
    // Make sure we have enough bytes for a CoAP message header.
    if (req->len < sizeof(coap_msg_t)) {
        coap_discard(req);
        return;
    }
    // Check CoAP version.
    switch (req->msg->ver) {
        case COAP_VERSION:
            break;
        default:
            coap_discard(req);
            return;
    }
    // Check token length.
    if (req->msg->tkl > COAP_MAX_TKL || req->len < sizeof(*req->msg) + req->msg->tkl) {
        coap_discard(req);
        return;
    }
    // Check message type.
    switch (req->msg->type) {
        case COAP_TYPE_CONFIRMABLE:
        case COAP_TYPE_NON_CONFIRMABLE:
            break;
        case COAP_TYPE_ACK:
           coap_handle_ack(req, &root);
           return;
        case COAP_TYPE_RESET:
           coap_handle_reset(req, &root);
           return;
        default:
            // Unrecongized type.
            coap_discard(req);
            return;
    }
    switch (req->msg->code.code_class) {
        case COAP_REQ:
            break;
        default:
            // All of our outgoing messages are responses.  Thus, we  expect no
            // incoming messages other than requests.  If we do see any other
            // types, we can safely ignore these.
            coap_discard(req);
            return;
    }
    // Clear our ACK-transmission flag.
    ZCOAP_MEMSET(&req->state, 0, sizeof(req->state));
    // This is a valid request!  Inject into the server!
    root.singleton = true; // Project singleton characteristic into children.
    inject_coap_req(req, &root);
}

/**
 * Helper function for iter_coap_sort.  Sort all children of the passed node
 * by node->name.
 *
 * @param node tree node for which to sort children
 */
static void coap_sort_children(const coap_node_t * const node)
{
    size_t count = coap_count_children(node);
    if (!count) {
        return;
    }
    qsort(node->children, count, sizeof(node->children[0]), coap_node_cmp);
}

static coap_code_t iter_coap_sort(coap_node_t * const node, const void *data); // forward declaration

/**
 * Recursive CoAP URI tree sort iterator.  Also executes init on nodes where
 * init is specified.
 *
 * @param node root node from which to recurse
 * @param data unused
 * @return 0 on success, else an appropriate CoAP error code
 */
static coap_code_t iter_coap_sort(coap_node_t * const node, const void *data)
{
    ZCOAP_ASSERT(node->observable ? node->singleton && get_sub_map(node) != NULL : true);
    if (node->init) {
        (*node->init)(node);
    }
    ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: identifying and sorting node with path segment '%s'", __func__, node->name);
    coap_sort_children(node);
    for (coap_node_t * const *c = node->children; c != NULL && *c != NULL; ++c) {
        coap_node_t child = **c;
        child.parent = node;
        child.singleton = child.singleton ? false : node->singleton; // singleton is inherited
        ZCOAP_ASSERT(!iter_coap_sort(&child, data));
    }
    if (node->gen) {
        ZCOAP_ASSERT(!(*node->gen)(node, &iter_coap_sort, data));
    }
    if (node->validate) {
        const char *err = (*node->validate)(node, node->data);
        ZCOAP_ASSERT(!err);
    }
    return 0;
}

/**
 * Sort the CoAP URI tree starting at the passed root node and and execute
 * init at each node where an init is specified.  Sort allows us to use bsearch
 * for faster request URI match.
 *
 * A tree must be processed by init before it is passed to coap_rx for the
 * first time.
 *
 * @param root pointer to the root node of the tree to init
 */
void coap_init(coap_node_t root)
{
    ZCOAP_ASSERT(!root.observable); // Observation of root node not supported.
    root.singleton = true; // Project singleton characteristic into children.
    iter_coap_sort(&root, NULL);
}

/*********** Begin general request processing utililty functions. ************/

/**
 * Count the number of query options in the passed request.  Parses req for its
 * options if caller passes opts == NULL.
 *
 * @param req CoAP request to parse
 * @param nopts number of options in the request
 * @param opts parsed options from the passed request, or null if the caller doesn't have these
 * @param nqueryopts (out) number of query options found
 * @return 0 on success, else a CoAP error code
 */
coap_code_t coap_count_query_opts(coap_req_data_t* const req, size_t nopts, const coap_msg_opt_t opts[], size_t* const nqueryopts)
{
    if ((opts == NULL && req == NULL) || nqueryopts == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_code_t rc;
    if (opts == NULL && (rc = coap_count_opts(req, &nopts))) {
        return rc;
    }
    if (nopts == 0) {
        *nqueryopts = 0;
        return 0;
    }
    if (nopts > ZCOAP_MAX_PAYLOAD_OPTS) {
        ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: too many options", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
#ifdef __GNUC__
    coap_msg_opt_t lopts[nopts];
#else
    coap_msg_opt_t lopts[ZCOAP_MAX_PAYLOAD_OPTS];
#endif /* __GNUC__ */

    if (opts == NULL) {
        if ((rc = coap_get_opts(req, nopts, lopts))) {
            return rc;
        }
    } else {
        ZCOAP_MEMCPY(lopts, opts, sizeof(lopts));
    }
    // Find *an* occurrence of a URI query option.
    const coap_msg_opt_t key = { .num = COAP_OPT_URI_QUERY };
    coap_msg_opt_t *a_query_opt = bsearch(&key, lopts, nopts, sizeof(lopts[0]), &opt_cmp);
    if (a_query_opt == NULL) {
        *nqueryopts = 0;
        return 0;
    }
    // Now find the *first* occurrence of a URI query option.
    coap_msg_opt_t *first_query_opt;
    for (coap_msg_opt_t *opt = a_query_opt; ; --opt) {
        if (opt->num != COAP_OPT_URI_QUERY) {
            first_query_opt = opt + 1;
            break;
        }
        if (opt == lopts) {
            first_query_opt = opt;
            break;
        }
    }
    // Now count URI query options.
    *nqueryopts = 0;
    coap_msg_opt_t *end = lopts + nopts;
    for (coap_msg_opt_t *opt = first_query_opt; opt < end && opt->num == COAP_OPT_URI_QUERY; ++opt) {
        ++*nqueryopts;
    }
    return 0;
}

/**
 * Get the query options from the passed request.   Parses req for its options
 * if caller passes opts == NULL.
 *
 * @param req CoAP request to parse for query options.
 * @param nopts number of options in the request
 * @param opts parsed options from the passed request, or null if the caller doesn't have these
 * @param nqueryopts number of query options in the request
 * @param queryopts (out) written with the requests query options
 * @return 0 on success, else a CoAP error code
 */
coap_code_t coap_get_query_opts(coap_req_data_t* const req, size_t nopts, const coap_msg_opt_t opts[], const size_t nqueryopts, coap_msg_opt_t* const queryopts)
{
    if (nqueryopts == 0) {
        return 0;
    }
    if ((opts == NULL && req == NULL) || queryopts == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_code_t rc;
    if (opts == NULL && (rc = coap_count_opts(req, &nopts))) {
        return rc;
    }
    if (nqueryopts > nopts) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: options parse error", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }

    if (nopts > ZCOAP_MAX_PAYLOAD_OPTS) {
        ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: too many options", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
#ifdef __GNUC__
    coap_msg_opt_t lopts[nopts];
#else
    coap_msg_opt_t lopts[ZCOAP_MAX_PAYLOAD_OPTS];
#endif /* __GNUC__ */

    if (opts == NULL) {
        if ((rc = coap_get_opts(req, nopts, lopts))) {
            return rc;
        }
    } else {
        ZCOAP_MEMCPY(lopts, opts, sizeof(lopts));
    }
    // Find *an* occurrence of a URI query option.
    const coap_msg_opt_t key = { .num = COAP_OPT_URI_QUERY };
    coap_msg_opt_t *a_query_opt = bsearch(&key, lopts, nopts, sizeof(lopts[0]), &opt_cmp);
    if (a_query_opt == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: unable to locate query option", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    // Now find the *first* occurrence of a URI query option.
    coap_msg_opt_t *first_query_opt;
    for (coap_msg_opt_t *opt = a_query_opt; ; --opt) {
        if (opt->num != COAP_OPT_URI_QUERY) {
            first_query_opt = opt + 1;
            break;
        }
        if (opt == lopts) {
            first_query_opt = opt;
            break;
        }
    }
    // Now publish.
    coap_msg_opt_t *end = lopts + nopts;
    if (first_query_opt + nqueryopts > end) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: options parse error", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    ZCOAP_MEMCPY(queryopts, first_query_opt, nqueryopts * sizeof(queryopts[0]));
    return 0;
}

/**
 * Get a size1 option (if any exists) from the passed request.  Parses req for
 * its options if caller passes opts == NULL.
 *
 * @param req request to search for a size1 option
 * @param nopts number of options in the request
 * @param opts parsed request options, or null if not available
 * @param found (out) written to true if size1 is found, else written to false
 * @param size1 (out) size1 option value
 * @return 0 on success, else a CoAP error code; note that size1 not found is NOT an error
 */
uint8_t coap_get_size1(coap_req_data_t* const req, size_t nopts, const coap_msg_opt_t opts[], bool* const found, uint32_t* const size1)
{
    if ((opts == NULL && req == NULL) || found == NULL || size1 == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_code_t rc;
    if (opts == NULL && (rc = coap_count_opts(req, &nopts))) {
        return rc;
    }
    if (nopts == 0) {
        *found = false;
        return 0;
    }
    // In the bsearch, we will find *an* occurrence of a size1 option. If the
    // requesting agent has enclosed more than one, that's a protocol violation
    // on their part and not our problem.
    coap_msg_opt_t msg_size1;
    if (opts == NULL) {

        if (nopts > ZCOAP_MAX_PAYLOAD_OPTS) {
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: too many options", __func__);
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
#ifdef __GNUC__
        coap_msg_opt_t lopts[nopts];
#else
        coap_msg_opt_t lopts[ZCOAP_MAX_PAYLOAD_OPTS];
#endif /* __GNUC__ */

        if ((rc = coap_get_opts(req, nopts, lopts))) {
            return rc;
        }
        const coap_msg_opt_t key = { .num = COAP_OPT_SIZE1 };
        coap_msg_opt_t *_msg_size1 = bsearch(&key, lopts, nopts, sizeof(lopts[0]), &opt_cmp);
        if (_msg_size1 == NULL) {
            *found = false;
            return 0;
        }
        msg_size1 = *_msg_size1;
    } else {
        const coap_msg_opt_t key = { .num = COAP_OPT_SIZE1 };
        coap_msg_opt_t *_msg_size1 = bsearch(&key, opts, nopts, sizeof(opts[0]), &opt_cmp);
        if (_msg_size1 == NULL) {
            *found = false;
            return 0;
        }
        msg_size1 = *_msg_size1;
    }
    *found = true;
    if (!msg_size1.len) {
        // Per RFC 7252, a zero-length option value field is simply empty.  And
        // this is legal for the size1 designator.  We'll interpret this as
        // unspecified / don't care.  To the caller, this will be equivalent to
        // the case where no size1 option was included at all.
        *found = false;
        return 0;
    } else if (msg_size1.len > sizeof(uint32_t)) {
        // size1 values larger than 4 bytes violate the RFC
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
    }
    memset(size1, 0, sizeof(*size1));
    ZCOAP_MEMCPY(size1, msg_size1.val, msg_size1.len);
    *size1 = ZCOAP_NTOHL(*size1);
    return 0;
}

/************** Begin string-to-numerical conversion functions. **************/

#if ULLONG_MAX == UINT64_MAX && LLONG_MAX == INT64_MAX
/**
 * Interpret the passed buffer as an ascii representation of an unsigned
 * long long integer and, if successfully parsed, write to 'out'.
 *
 * On success, returns 0.  On failure, returns an error from errno.h.  If the
 * user has passed non-null for output parameter 'size1' and the payload is too
 * large, the function returns ENOMEM and writes the maximum size, which the
 * caller can use to construct a size1 option for the client error response.
 *
 * Note: This function uses the c library function strtoull with radix
 *       unspecified.  Valid input representations are therefore:
 *
 *          * decimal integers in the range 0 to 18446744073709551615
 *          * octal integers in the range 0 to 01777777777777777777777
 *          * hexidecimal integers in the range 0x0 to 0xFFFFFFFFFFFFFFFF
 *
 * Note: Some embedded C library strtoull implementations may not set errno
 *       on error.  And even if they do, we are left in a bind.  Where is
 *       errno?  Is this thread safe?
 *
 *       A concrete example: With reference to strtoull, the Microchip 16-Bit
 *       Language Tools Libraries Reference Manual, Document DS50001456J
 *       describes:
 *
 *           "If a range error occurs, errno will be set."
 *
 *       This function, however, does NOT set errno on parse or range error.
 *
 *       It is suspected that this errno behavior, however undesirable, is
 *       employed to make this function thread-safe (whereas otherwise it would
 *       not be).  Regardless, we find ourselves in a position where we are
 *       unable to leverage errno to differentiate overflow conditions from
 *       those cases where the passed buffer does actually contain ULLONG_MAX.
 *
 *       So we presume the following of our strtoull:
 *
 *          * it will set and advance endptr on successful parse
 *          * it will return ULLONG_MAX on overflow
 *          * it may or may not set errno
 *          * but even it it sets errno, errno may not be thread safe
 *          * therefore, if strtoull returns ULLONG_MAX,
 *            we manually audit for under and overflow
 *
 *       With this strategy, we retain full coverage for error conditions and
 *       also avoid any thread safety implications associated with the use of
 *       errno.  We also have a strtoull call that will be somewhat immune to
 *       changes in library behavior.
 *
 * @param ascii text to parse
 * @param len text length in bytes
 * @param out (out) number parsed from the caller-provided text
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_ullong(const void * const ascii, const size_t len, unsigned long long * const out)
{
    if (ascii == NULL || out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }

    // We bounds check incoming data for ZCOAP_MAX_BUF_SIZE.  We can't allow
    // clients to inject data that will grow our stack unreasonably.
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
    }

#ifdef __GNUC__
    char buf[len + 1];
#else
    char buf[ZCOAP_MAX_BUF_SIZE];
#endif /* __GNUC__ */

    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtoull(buf, &endptr, 0);
    if (!endptr || endptr == buf) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    } else if (*out == ULLONG_MAX) {
        // Our c library's strtoull may not set errno, or may not have any
        // thread safety around errno.  So we must manually verify the passed
        // buffer doesn't actually contain an integer minimum or maximum value.
        // Only when we've ruled this out can we declare this an error condition.
        char *tok;
        if ((tok = strstr(buf, "0x")) || (tok = strstr(buf, "0X"))) {
            for (size_t i = 0; i < strlen("ffffffffffffffff"); ++i) { // tolower for 0xF
                if (tok[i] == 'F') {
                    tok[i] = 'f';
                }
            }
            if (   (tok = strstr(tok, "ffffffffffffffff"))
                && !strpbrk(tok + strlen("ffffffffffffffff"), "0123456789abcdefABCDEF")) {
               return 0;
            } else {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
        } else if (   (tok = strstr(buf, "18446744073709551615"))
                   && !strpbrk(tok + strlen("18446744073709551615"), "0123456789")) {
            return 0;
        } else if (   (tok = strstr(buf, "01777777777777777777777"))
                   && !strpbrk(tok + strlen("01777777777777777777777"), "01234567")) {
            return 0;
        } else {
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    }
    return 0;
}

/**
 * Interpret the passed buffer as an ascii representation of a long long int
 * and, if successfully parsed, write to 'out'.
 *
 * On success, returns 0.  On failure, returns an error from errno.h.  If the
 * user has passed non-null for output parameter 'size1' and the payload is too
 * large, the function returns ENOMEM and writes the maximum size, which the
 * caller can use to construct a size1 option for the client error response.
 *
 * Note: This function uses the standard c library function strtoll with radix
 *       unspecified.  Valid input representations are therefore:
 *
 *          * decimal integers in the range -9223372036854775808 to 9223372036854775807
 *          * octal integers in the range 0 to 01777777777777777777777
 *          * hexidecimal integers in the range 0x0 to 0xFFFFFFFFFFFFFFFF
 *
 * Note: Some embedded C library strtoll implementations may not set errno
 *       on error.  And even if they do, we are left in a bind.  Where is
 *       errno?  Is this thread safe?
 *
 *       A concrete example: With reference to strtoll, the Microchip 16-Bit
 *       Language Tools Libraries Reference Manual, Document DS50001456J
 *       describes:
 *
 *           "If a range error occurs, errno will be set."
 *
 *       This function, however, does NOT set errno on parse or range error.
 *
 *       It is suspected that this errno behavior, however undesirable, is
 *       employed to make this function thread-safe (whereas otherwise it would
 *       not be).  Regardless, we find ourselves in a position where we are
 *       unable to leverage errno to differentiate overflow conditions from
 *       those cases where the passed buffer does actually contain ULLONG_MAX.
 *
 *       So we presume the following of our strtoll:
 *
 *          * it will set and advance endptr on successful parse
 *          * it will return LLONG_MIN or LLONG_MAX on overflow
 *          * it may or may not set errno
 *          * but even it it sets errno, errno may not be thread safe
 *          * therefore, if strtoll returns LLONG_MIN or LLONG_MAX,
 *            we manually audit for under and overflow
 *
 *       With this strategy, we retain full coverage for error conditions and
 *       also avoid any thread safety implications associated with the use of
 *       errno.  We also have a strtoll call that will be somewhat immune to
 *       changes in library behavior.
 *
 * @param ascii text to parse
 * @param len text length in bytes
 * @param out (out) number parsed from the caller-provided text
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_llong(const void * const ascii, const size_t len, long long * const out)
{
    if (ascii == NULL || out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }

    // We bounds check incoming data for ZCOAP_MAX_BUF_SIZE.  We can't allow
    // clients to inject data that will grow our stack unreasonably.
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
    }

#ifdef __GNUC__
    char buf[len + 1];
#else
    char buf[ZCOAP_MAX_BUF_SIZE];
#endif /* __GNUC__ */

    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtoll(buf, &endptr, 0);
    if (!endptr || endptr == buf) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    } else if (*out == LLONG_MAX) {
        // Our c library's strtull may not set errno, or may not have any
        // thread safety around errno.  So we must manually verify the passed
        // buffer doesn't actually contain an integer minimum or maximum value.
        // Only when we've ruled this out can we declare this an error condition.
        char *tok;
        if ((tok = strstr(buf, "0x")) || (tok = strstr(buf, "0X"))) {
            for (size_t i = 1; i < strlen("fffffffffffffff"); ++i) { // tolower for 0xF
                if (tok[i] == 'F') {
                    tok[i] = 'f';
                }
            }
            if (   (tok = strstr(tok, "7fffffffffffffff"))
                && !strpbrk(tok + strlen("7fffffffffffffff"), "0123456789abcdefABCDEF")) {
                return 0;
            } else {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
        } else if (   (tok = strstr(buf, "9223372036854775807"))
                   && !strpbrk(tok + strlen("9223372036854775807"), "0123456789")) {
            return 0;
        } else if (   (tok = strstr(buf, "0777777777777777777777"))
                   && !strpbrk(tok + strlen("0777777777777777777777"), "01234567")) {
            return 0;
        } else {
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    } else if (*out == LLONG_MIN) {
        // Likewise, verify that buffer isn't actually specifying LLONG_MIN.
        char *tok;
        if (   ((tok = strstr(buf, "0x8000000000000000")) || (tok = strstr(buf, "0X8000000000000000")))
            && !strpbrk(tok + strlen("0x8000000000000000"), "0123456789abcdefABCDEF")) {
            return 0;
        } else if (   (tok = strstr(buf, "-9223372036854775808"))
                   && !strpbrk(tok + strlen("-9223372036854775808"), "0123456789")) {
            return 0;
        } else if (   (tok = strstr(buf, "01000000000000000000000"))
                   && !strpbrk(tok + strlen("01000000000000000000000"), "01234567")) {
            return 0;
        } else {
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    }
    return 0;
}
#else
#error ullong and llong must be 64-bit!
#endif /* ULLONG_MAX == UINT64_MAX && LLONG_MAX == INT64_MAX */

#if ULONG_MAX == ULLONG_MAX && LONG_MAX == LLONG_MAX
coap_code_t coap_parse_ulong(const void * const ascii, const size_t len, unsigned long * const out)
{
    return coap_parse_ullong(ascii, len, (unsigned long long *)out); // we checked width; this is OK
}

coap_code_t coap_parse_long(const void * const ascii, const size_t len, long * const out)
{
    return coap_parse_llong(ascii, len, (long long *)out); // we checked width; this is OK
}
#elif ULONG_MAX == UINT32_MAX && LONG_MAX == INT32_MAX
/**
 * Interpret the passed buffer as an ascii representation of an unsigned long
 * and, if successfully parsed, write to 'out'.
 *
 * On success, returns 0.  On failure, returns an error from errno.h.  If the
 * user has passed non-null for output parameter 'size1' and the payload is too
 * large, the function returns ENOMEM and writes the maximum size, which the
 * caller can use to construct a size1 option for the client error response.
 *
 * Note: This function uses the c library function strtoul with radix
 *       unspecified.  Valid input representations are therefore:
 *
 *          * decimal integers in the range 0 to 4294967295
 *          * octal integers in the range 0 to 037777777777
 *          * hexidecimal integers in the range 0x0 to 0xFFFFFFFF
 *
 * Note: Some embedded C library strtoul implementations may not set errno
 *       on error.  And even if they do, we are left in a bind.  Where is
 *       errno?  Is this thread safe?
 *
 *       A concrete example: With reference to strtoul, the Microchip 16-Bit
 *       Language Tools Libraries Reference Manual, Document DS50001456J
 *       describes:
 *
 *           "If a range error occurs, errno will be set."
 *
 *       This function, however, does NOT set errno on parse or range error.
 *
 *       It is suspected that this errno behavior, however undesirable, is
 *       employed to make this function thread-safe (whereas otherwise it would
 *       not be).  Regardless, we find ourselves in a position where we are
 *       unable to leverage errno to differentiate overflow conditions from
 *       those cases where the passed buffer does actually contain ULLONG_MAX.
 *
 *       So we presume the following of our strtoul:
 *
 *          * it will set and advance endptr on successful parse
 *          * it will return ULONG_MAX on overflow
 *          * it may or may not set errno
 *          * but even it it sets errno, errno may not be thread safe
 *          * therefore, if strtoul returns ULONG_MIN or ULONG_MAX,
 *            we manually audit for under and overflow
 *
 *       With this strategy, we retain full coverage for error conditions and
 *       also avoid any thread safety implications associated with the use of
 *       errno.  We also have a strtoul call that will be somewhat immune to
 *       changes in library behavior.
 *
 * @param ascii text to parse
 * @param len text length in bytes
 * @param out (out) number parsed from the caller-provided text
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_ulong(const void * const ascii, const size_t len, unsigned long * const out)
{
    if (ascii == NULL || out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }

    // We bounds check incoming data for ZCOAP_MAX_BUF_SIZE.  We can't allow
    // clients to inject data that will grow our stack unreasonably.
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
    }

#ifdef __GNUC__
    char buf[len + 1];
#else
    char buf[ZCOAP_MAX_BUF_SIZE];
#endif /* __GNUC__ */

    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtoul(buf, &endptr, 0);
    if (!endptr || endptr == buf) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    } else if (*out == ULONG_MAX) {
        // Our c library's strtoul may not set errno, or may not have any
        // thread safety around errno.  So we must manually verify the passed
        // buffer doesn't actually contain an integer minimum or maximum value.
        // Only when we've ruled this out can we declare this an error condition.
        char *tok;
        if ((tok = strstr(buf, "0x")) || (tok = strstr(buf, "0X"))) {
            for (size_t i = 0; i < strlen("ffffffff"); ++i) { // tolower for 0xF
                if (tok[i] == 'F') {
                    tok[i] = 'f';
                }
            }
            if (   (tok = strstr(tok, "ffffffff"))
                && !strpbrk(tok + strlen("ffffffff"), "0123456789abcdefABCDEF")) {
               return 0;
            } else {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
        } else if (   (tok = strstr(buf, "4294967295"))
                   && !strpbrk(tok + strlen("4294967295"), "0123456789")) {
            return 0;
        } else if (   (tok = strstr(buf, "037777777777"))
                   && !strpbrk(tok + strlen("037777777777"), "01234567")) {
            return 0;
        } else {
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    }
    return 0;
}

/**
 * Interpret the passed buffer as an ascii representation of a long int and,
 * if successfully parsed, write to 'out'.
 *
 * On success, returns 0.  On failure, returns an error from errno.h.  If the
 * user has passed non-null for output parameter 'size1' and the payload is too
 * large, the function returns ENOMEM and writes the maximum size, which the
 * caller can use to construct a size1 option for the client error response.
 *
 * Note: This function uses the standard c library function strtol with radix
 *       unspecified.  Valid input representations are therefore:
 *          * decimal integers in the range -2147483648 to 2147483647
 *          * octal integers in the range 0 to 037777777777
 *          * hexidecimal integers in the range 0x0 to 0xFFFFFFFF
 *
 * Note: Some embedded C library strtol implementations may not set errno
 *       on error.  And even if they do, we are left in a bind.  Where is
 *       errno?  Is this thread safe?
 *
 *       A concrete example: With reference to strtol, the Microchip 16-Bit
 *       Language Tools Libraries Reference Manual, Document DS50001456J
 *       describes:
 *
 *           "If a range error occurs, errno will be set."
 *
 *       This function, however, does NOT set errno on parse or range error.
 *
 *       It is suspected that this errno behavior, however undesirable, is
 *       employed to make this function thread-safe (whereas otherwise it would
 *       not be).  Regardless, we find ourselves in a position where we are
 *       unable to leverage errno to differentiate overflow conditions from
 *       those cases where the passed buffer does actually contain ULLONG_MAX.
 *
 *       So we presume the following of our strtol:
 *
 *          * it will set and advance endptr on successful parse
 *          * it will return LONG_MIN or LONG_MAX on overflow
 *          * it may or may not set errno
 *          * but even it it sets errno, errno may not be thread safe
 *          * therefore, if strtol returns LONG_MIN or LONG_MAX,
 *            we manually audit for under and overflow
 *
 *       With this strategy, we retain full coverage for error conditions and
 *       also avoid any thread safety implications associated with the use of
 *       errno.  We also have a strtol call that will be somewhat immune to
 *       changes in library behavior.
 *
 * @param ascii text to parse
 * @param len text length in bytes
 * @param out (out) number parsed from the caller-provided text
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_long(const void * const ascii, const size_t len, long * const out)
{
    if (ascii == NULL || out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }

    // We bounds check incoming data for ZCOAP_MAX_BUF_SIZE.  We can't allow
    // clients to inject data that will grow our stack unreasonably.
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
    }

#ifdef __GNUC__
    char buf[len + 1];
#else
    char buf[ZCOAP_MAX_BUF_SIZE];
#endif /* __GNUC__ */

    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtol(buf, &endptr, 0);
    if (!endptr || endptr == buf) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    } else if (*out == LONG_MAX) {
        // Our c library's strtol may not set errno, or may not have any
        // thread safety around errno.  So we must manually verify the passed
        // buffer doesn't actually contain an integer minimum or maximum value.
        // Only when we've ruled this out can we declare this an error condition.
        char *tok;
        if ((tok = strstr(buf, "0x")) || (tok = strstr(buf, "0X"))) {
            for (size_t i = 1; i < strlen("fffffff"); ++i) { // tolower for 0xF
                if (tok[i] == 'F') {
                    tok[i] = 'f';
                }
            }
            if (   (tok = strstr(tok, "7fffffff"))
                && !strpbrk(tok + strlen("7fffffff"), "0123456789abcdefABCDEF")) {
               return 0;
            } else {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
        } else if (   (tok = strstr(buf, "2147483647"))
                   && !strpbrk(tok + strlen("2147483647"), "0123456789")) {
            return 0;
        } else if (   (tok = strstr(buf, "017777777777"))
                   && !strpbrk(tok + strlen("017777777777"), "01234567")) {
            return 0;
        } else {
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    } else if (*out == LONG_MIN) {
        // Likewise, verify that buffer isn't actually specifying LONG_MIN.
        char *tok;
        if (   ((tok = strstr(buf, "0x80000000")) || (tok = strstr(buf, "0X80000000")))
            && !strpbrk(tok + strlen("0x80000000"), "0123456789abcdefABCDEF")) {
            return 0;
        } else if (   (tok = strstr(buf, "-2147483648"))
                   && !strpbrk(tok + strlen("-2147483648"), "0123456789")) {
            return 0;
        } else if (   (tok = strstr(buf, "020000000000"))
                   && !strpbrk(tok + strlen("020000000000"), "01234567")) {
            return 0;
        } else {
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    }
    return 0;
}
#endif /* ULONG_MAX == UINT32_MAX && LONG_MAX == INT32_MAX */

/**
 * Interpret the passed buffer as an ascii representation of a unsigned integer
 * and, if successfully parsed, write to 'out'.
 *
 * This is a shallow wrapper for coap_parse_ulong.  See coap_parse_ulong for
 * more details.
 *
 * @param ascii text to parse
 * @param len text length in bytes
 * @param out (out) number parsed from the caller-provided text
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_uint(const void * const ascii, const size_t len, unsigned * const out)
{
    if (out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_code_t rc;
    unsigned long ulong;
    if ((rc = coap_parse_ulong(ascii, len, &ulong))) {
        return rc;
    }
    if (ulong > UINT_MAX) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    *out = ulong;
    return 0;
}

/**
 * Interpret the passed buffer as an ascii representation of an integer and, if
 * successfully parsed, write to 'out'.
 *
 * This is a shallow wrapper for coap_parse_long.  See coap_parse_long for
 * more details.
 *
 * @param ascii text to parse
 * @param len text length in bytes
 * @param out (out) number parsed from the caller-provided text
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_int(const void * const ascii, const size_t len, int * const out)
{
    if (out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_code_t rc;
    long slong;
    if ((rc = coap_parse_long(ascii, len, &slong))) {
        return rc;
    }
    if (slong < INT_MIN || slong > INT_MAX) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    *out = slong;
    return 0;
}

/**
 * Interpret the passed buffer as an ascii representation of a float and, if
 * successfully parsed, write to 'out'.
 *
 * On success, returns 0.  On failure, returns an error from errno.h.  If the
 * user has passed non-null for output parameter 'size1' and the payload is too
 * large, the function returns ENOMEM and writes the maximum size, which the
 * caller can use to construct a size1 option for the client error response.
 *
 * Note: Some embedded C library strtof implementations may not set errno
 *       on error.  And even if they do, we are left in a bind.  Where is
 *       errno?  Is this thread safe?
 *
 *       A concrete example: With reference to strtod, the Microchip 16-Bit
 *       Language Tools Libraries Reference Manual, Document DS50001456J
 *       describes:
 *
 *           "If a range error occurs, errno will be set."
 *
 *       This function, however, does NOT set errno on parse or range error.
 *
 *       It is suspected that this errno behavior, however undesirable, is
 *       employed to make this function thread-safe (whereas otherwise it would
 *       not be).  Regardless, we find ourselves in a position where we are
 *       unable to leverage errno to differentiate overflow conditions from
 *       those cases where the passed buffer does actually contain ULLONG_MAX.
 *
 *       So we presume the following of our strtol:
 *
 *          * it will set and advance endptr on successful parse
 *          * it may return HUGE_VALF or -HUGE_VALF on overflow
 *          * it will return a value equal or smaller in magnitude to the smallest normal on underflow
 *          * it may, as in the case of XC16, also return a value equal or smaller in magntude to the smallest normal on overflow
 *          * it may or may not set errno
 *          * but even it it sets errno, errno may not be thread safe
 *          * therefore, we presume that all returns equal in magnitude to HUGE_VALF,
 *          * or equal to or smaller than the smallest normal are overflow or underflow
 *
 *       With this strategy, we retain full coverage for error conditions and
 *       also avoid any thread safety implications associated with the use of
 *       errno.  We will presume that the set of values that may be erroneously
 *       called out as underflow or overflow are not particularly useful to the
 *       application.
 *
 * @param ascii text to parse
 * @param len text length in bytes
 * @param out (out) number parsed from the caller-provided text
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_float(const void * const ascii, const size_t len, float * const out)
{
    if (ascii == NULL || out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }

    // We bounds check incoming data for ZCOAP_MAX_BUF_SIZE.  We can't allow
    // clients to inject data that will grow our stack unreasonably.
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
    }

#ifdef __GNUC__
    char buf[len + 1];
#else
    char buf[ZCOAP_MAX_BUF_SIZE];
#endif /* __GNUC__ */

    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtof(buf, &endptr);
    if (!endptr || endptr == buf) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    } else if (fabsf(*out) == HUGE_VALF) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ); // presume overflow
    } else {
        int exponent;
        frexpf(*out, &exponent);
        if (exponent <= -126) { // 2^-126 is the smallest normal single-precision IEEE-754 float
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ); // presume underflow
        }
    }
    return 0;
}

/**
 * Interpret the passed buffer as an ascii representation of a double and, if
 * successfully parsed, write to 'out'.
 *
 * On success, returns 0.  On failure, returns an error from errno.h.  If the
 * user has passed non-null for output parameter 'size1' and the payload is too
 * large, the function returns ENOMEM and writes the maximum size, which the
 * caller can use to construct a size1 option for the client error response.
 *
 * Note: Some embedded C library strtod implementations may not set errno
 *       on error.  And even if they do, we are left in a bind.  Where is
 *       errno?  Is this thread safe?
 *
 *       A concrete example: With reference to strtod, the Microchip 16-Bit
 *       Language Tools Libraries Reference Manual, Document DS50001456J
 *       describes:
 *
 *           "If a range error occurs, errno will be set."
 *
 *       This function, however, does NOT set errno on parse or range error.
 *
 *       It is suspected that this errno behavior, however undesirable, is
 *       employed to make this function thread-safe (whereas otherwise it would
 *       not be).  Regardless, we find ourselves in a position where we are
 *       unable to leverage errno to differentiate overflow conditions from
 *       those cases where the passed buffer does actually contain ULLONG_MAX.
 *
 *       So we presume the following of our strtol:
 *
 *          * it will set and advance endptr on successful parse
 *          * it may return HUGE_VAL or -HUGE_VAL on overflow
 *          * it will return a value equal or smaller in magnitude to the smallest normal on underflow
 *          * it may, as in the case of XC16, also return a value equal or smaller in magntude to the smallest normal on overflow
 *          * it may or may not set errno
 *          * but even it it sets errno, errno may not be thread safe
 *          * therefore, we presume that all returns equal in magnitude to HUGE_VAL,
 *          * or equal to or smaller than the smallest normal are overflow or underflow
 *
 *       With this strategy, we retain full coverage for error conditions and
 *       also avoid any thread safety implications associated with the use of
 *       errno.  We will presume that the set of values that may be erroneously
 *       called out as underflow or overflow are not particularly useful to the
 *       application.
 *
 * @param ascii text to parse
 * @param len text length in bytes
 * @param out (out) number parsed from the caller-provided text
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_double(const void * const ascii, const size_t len, ZCOAP_DOUBLE * const out)
{
    if (ascii == NULL || out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }

    // We bounds check incoming data for ZCOAP_MAX_BUF_SIZE.  We can't allow
    // clients to inject data that will grow our stack unreasonably.
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
    }

#ifdef __GNUC__
    char buf[len + 1];
#else
    char buf[ZCOAP_MAX_BUF_SIZE];
#endif /* __GNUC__ */

    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtod(buf, &endptr);
    if (!endptr || endptr == buf) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    } else if (fabs(*out) == HUGE_VAL) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ); // presume overflow
    } else {
        int exponent;
        frexp(*out, &exponent);
        if (exponent <= -1022) { // 2^-1022 is the smallest normal double-precision IEEE-754 float
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ); // presume underflow
        }
    }
    return 0;
}

/**
 * Parse a uint64 from a CBOR-format CoAP payload.
 *
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
static coap_code_t coap_parse_cbor_u64(size_t len, const void *payload, uint64_t * const out)
{
    if (payload == NULL || out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (len < sizeof(cbor_t)) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    cbor_t cbor;
    ZCOAP_MEMCPY(&cbor, payload, sizeof(cbor));
    len -= sizeof(cbor);
    payload = (uint8_t *)payload + sizeof(cbor);
    switch (cbor.type) {
        case CBOR_MAJOR_TYPE_UNSIGNED:
            if (cbor.add < CBOR_ADD_INFO_UINT8) {
                uint8_t pval = cbor.add;
                *out = pval;
                return 0;
            } else if (cbor.add == CBOR_ADD_INFO_UINT8) {
                uint8_t pval;
                if (len != sizeof(pval)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                *out = pval;
                return 0;
            } else if (cbor.add == CBOR_ADD_INFO_UINT16) {
                uint16_t pval;
                if (len != sizeof(pval)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                pval = ZCOAP_NTOHS(pval);
                *out = pval;
                return 0;
            } else if (cbor.add == CBOR_ADD_INFO_UINT32) {
                uint32_t pval;
                if (len != sizeof(pval)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                pval = ZCOAP_NTOHL(pval);
                *out = pval;
                return 0;
            } else if (cbor.add == CBOR_ADD_INFO_UINT64) {
                uint64_t pval;
                if (len != sizeof(pval)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                pval = ZCOAP_NTOHLL(pval);
                *out = pval;
                return 0;
            } else {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
            }
        case CBOR_MAJOR_TYPE7:
            switch (cbor.add) {
                case CBOR_ADD_INFO_HALF: {
                    half_t half;
                    if (len != sizeof(half)) {
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                    }
                    ZCOAP_MEMCPY(&half, payload, sizeof(half));
                    half = ZCOAP_NTOHH(half);
                    float pval = half_to_single(half);
                    if (pval < 0.0) {
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                    }
                    *out = pval;
                    if (pval - *out != 0.0) {
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                    }
                    return 0;
                }
                case CBOR_ADD_INFO_SINGLE: {
                    float pval;
                    if (len != sizeof(pval)) {
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                    }
                    ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                    pval = ZCOAP_NTOHF(pval);
                    if (pval < 0.0 || pval > UINT64_MAX) {
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                    }
                    *out = pval;
                    if (pval - *out != 0.0) {
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                    }
                    return 0;
                }
                case CBOR_ADD_INFO_DOUBLE: {
                    ZCOAP_DOUBLE pval;
                    if (len != sizeof(pval)) {
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                    }
                    ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                    pval = ZCOAP_NTOHD(pval);
                    if (pval < 0.0 || pval > UINT64_MAX) {
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                    }
                    *out = pval;
                    if (pval - *out != 0.0) {
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                    }
                    return 0;
                }
                default:
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
            }
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
}

/**
 * Parse a uint64 from a CoAP payload.
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_req_u64(const coap_ct_t ct, const size_t len, const void * const payload, uint64_t * const out)
{
    if (out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    switch (ct) {
        case COAP_FMT_CBOR:
            return coap_parse_cbor_u64(len, payload, out);
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.
    coap_code_t rc;
    unsigned long long ullong;
    if ((rc = coap_parse_ullong(payload, len, &ullong))) {
        return rc;
    }
    if (ullong > UINT64_MAX) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    *out = ullong;
    return 0;
}

/**
 * Parse an int64 from a CBOR-format CoAP payload.
 *
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
static coap_code_t coap_parse_cbor_i64(size_t len, const void *payload, int64_t * const out)
{
    if (payload == NULL || out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (len < sizeof(cbor_t)) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    cbor_t cbor;
    ZCOAP_MEMCPY(&cbor, payload, sizeof(cbor));
    len -= sizeof(cbor);
    payload = (uint8_t *)payload + sizeof(cbor);
    if (   cbor.type == CBOR_MAJOR_TYPE_UNSIGNED
        || cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
        if (cbor.add < CBOR_ADD_INFO_UINT8) {
            uint8_t pval = cbor.add;
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT8) {
            uint8_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT16) {
            uint16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT32) {
            uint32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT64) {
            uint64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            if (   (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE && pval - 1 > INT64_MAX)
                || pval > INT64_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else {
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
        }
    } else if (cbor.type == CBOR_MAJOR_TYPE7) {
        switch (cbor.add) {
            case CBOR_ADD_INFO_HALF: {
                half_t half;
                if (len != sizeof(half)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&half, payload, sizeof(half));
                half = ZCOAP_NTOHH(half);
                float pval = half_to_single(half);
                *out = pval;
                if (pval - *out != 0.0) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                return 0;
            }
            case CBOR_ADD_INFO_SINGLE: {
                float pval;
                if (len != sizeof(pval)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                pval = ZCOAP_NTOHF(pval);
                if (pval < INT64_MIN || pval > INT64_MAX) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                *out = pval;
                if (pval - *out != 0.0) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                return 0;
            }
            case CBOR_ADD_INFO_DOUBLE: {
                ZCOAP_DOUBLE pval;
                if (len != sizeof(pval)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                pval = ZCOAP_NTOHD(pval);
                if (pval < INT64_MIN || pval > INT64_MAX) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                *out = pval;
                if (pval - *out != 0.0) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                return 0;
            }
            default:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
        }
    } else {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
}

/**
 * Parse an int64 from a CoAP payload.
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_req_i64(const coap_ct_t ct, const size_t len, const void * const payload, int64_t * const out)
{
    if (out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    switch (ct) {
        case COAP_FMT_CBOR:
            return coap_parse_cbor_i64(len, payload, out);
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.
    coap_code_t rc;
    long long llong;
    if ((rc = coap_parse_llong(payload, len, &llong))) {
        return rc;
    }
    if (llong < INT64_MIN || llong > INT64_MAX) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    *out = llong;
    return 0;
}

/**
 * Parse a float from a CBOR-format CoAP payload.
 *
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
static coap_code_t coap_parse_cbor_float(size_t len, const void *payload, float * const out)
{
    if (payload == NULL || out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (len < sizeof(cbor_t)) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    cbor_t cbor;
    ZCOAP_MEMCPY(&cbor, payload, sizeof(cbor));
    len -= sizeof(cbor);
    payload = (uint8_t *)payload + sizeof(cbor);
    if (   cbor.type == CBOR_MAJOR_TYPE_UNSIGNED
        || cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
        if (cbor.add < CBOR_ADD_INFO_UINT8) {
            uint8_t pval = cbor.add;
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT8) {
            uint8_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT16) {
            uint16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT32) {
            uint32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT64) {
            uint64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else {
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
        }
    } else if (cbor.type == CBOR_MAJOR_TYPE7) {
        switch (cbor.add) {
            case CBOR_ADD_INFO_HALF: {
                half_t half;
                if (len != sizeof(half)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&half, payload, sizeof(half));
                half = ZCOAP_NTOHH(half);
                float pval = half_to_single(half);
                *out = pval;
                return 0;
            }
            case CBOR_ADD_INFO_SINGLE: {
                float pval;
                if (len != sizeof(pval)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                pval = ZCOAP_NTOHF(pval);
                *out = pval;
                return 0;
            }
            case CBOR_ADD_INFO_DOUBLE: {
                ZCOAP_DOUBLE pval;
                if (len != sizeof(pval)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                pval = ZCOAP_NTOHD(pval);
                if (fabs(pval) > FLT_MAX) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                *out = pval;
                return 0;
            }
            default:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
        }
    } else {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
}

/**
 * Parse a float from a CoAP payload
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_req_float(const coap_ct_t ct, const size_t len, const void * const payload, float * const out)
{
    switch (ct) {
        case COAP_FMT_CBOR:
            return coap_parse_cbor_float(len, payload, out);
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.
    return coap_parse_float(payload, len, out);
}

/**
 * Parse a double from a CBOR-format CoAP payload.
 *
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
static coap_code_t coap_parse_cbor_double(size_t len, const void *payload, ZCOAP_DOUBLE * const out)
{
    if (payload == NULL || out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (len < sizeof(cbor_t)) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    cbor_t cbor;
    ZCOAP_MEMCPY(&cbor, payload, sizeof(cbor));
    len -=  sizeof(cbor);
    payload = (uint8_t *)payload + sizeof(cbor);
    if (   cbor.type == CBOR_MAJOR_TYPE_UNSIGNED
        || cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
        if (cbor.add < CBOR_ADD_INFO_UINT8) {
            uint8_t pval = cbor.add;
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT8) {
            uint8_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT16) {
            uint16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT32) {
            uint32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else if (cbor.add == CBOR_ADD_INFO_UINT64) {
            uint64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            *out = pval;
            if (cbor.type == CBOR_MAJOR_TYPE_NEGATIVE) {
                *out = -*out;
            }
            return 0;
        } else {
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
        }
    } else if (cbor.type == CBOR_MAJOR_TYPE7) {
        switch (cbor.add) {
            case CBOR_ADD_INFO_HALF: {
                half_t half;
                if (len != sizeof(half)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&half, payload, sizeof(half));
                half = ZCOAP_NTOHH(half);
                float pval = half_to_single(half);
                *out = pval;
                return 0;
            }
            case CBOR_ADD_INFO_SINGLE: {
                float pval;
                if (len != sizeof(pval)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                pval = ZCOAP_NTOHF(pval);
                *out = pval;
                return 0;
            }
            case CBOR_ADD_INFO_DOUBLE: {
                ZCOAP_DOUBLE pval;
                if (len != sizeof(pval)) {
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
                }
                ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
                pval = ZCOAP_NTOHD(pval);
                *out = pval;
                return 0;
            }
            default:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
        }
    } else {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
}

/**
 * Parse a double from a CoAP payload.
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_req_double(const coap_ct_t ct, const size_t len, const void* const payload, ZCOAP_DOUBLE* const out)
{
    switch (ct) {
        case COAP_FMT_CBOR:
            return coap_parse_cbor_double(len, payload, out);
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.
    return coap_parse_double(payload, len, out);
}

// Shallow 16-bit and 32-bit wrappers for the uint64 and int64 parsers

/**
 * Parse a uint32 from a CoAP payload.
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_req_u32(const coap_ct_t ct, const size_t len, const void* const payload, uint32_t* const out)
{
    if (out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    uint64_t u64;
    coap_code_t rc;
    if ((rc = coap_parse_req_u64(ct, len, payload, &u64))) {
        return  rc;
    }
    if (u64 > UINT32_MAX) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    } else {
        *out = u64;
        return 0;
    }
}

/**
 * Parse an int32 from a CoAP payload.
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_req_i32(const coap_ct_t ct, const size_t len, const void* const payload, int32_t* const out)
{
    if (out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    int64_t i64;
    coap_code_t rc;
    if ((rc = coap_parse_req_i64(ct, len, payload, &i64))) {
        return  rc;
    }
    if (i64 > INT32_MAX || i64 < INT32_MIN) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    } else {
        *out = i64;
        return 0;
    }
}

/**
 * Parse a uint16 from a CoAP payload.
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_req_u16(const coap_ct_t ct, const size_t len, const void* const payload, uint16_t* const out)
{
    if (out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    uint32_t u32;
    coap_code_t rc;
    if ((rc = coap_parse_req_u32(ct, len, payload, &u32))) {
        return  rc;
    }
    if (u32 > UINT16_MAX) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    } else {
        *out = u32;
        return 0;
    }
}

/**
 * Parse a int16 from a CoAP payload.
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_req_i16(const coap_ct_t ct, const size_t len, const void* payload, int16_t* const out)
{
    if (out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    int32_t i32;
    coap_code_t rc;
    if ((rc = coap_parse_req_i32(ct, len, payload, &i32))) {
        return  rc;
    }
    if (i32 > INT16_MAX || i32 < INT16_MIN) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    } else {
        *out = i32;
        return 0;
    }
}

/**
 * Parse an boolean from a CoAP payload.  Transmit an appropriate CoAP error
 * status response on error.
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t coap_parse_req_bool(const coap_ct_t ct, const size_t len, const void* const payload, bool* const out)
{
    if (out == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    switch (ct) {
        case COAP_FMT_CBOR: {
            cbor_t cbor;
            if (len != sizeof(cbor)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&cbor, payload, sizeof(cbor));
            switch (cbor.type) {
                case CBOR_MAJOR_TYPE7:
                    switch (cbor.add) {
                        case CBOR_ADD_INFO_FALSE:
                            *out = false;
                            return 0;
                        case CBOR_ADD_INFO_TRUE:
                            *out = true;
                            return 0;
                        default:
                            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
                    }
                default:
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
            }
        }
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.

    // First, parse for our truthiness strings.
    if (len >= strlen(ZCOAP_TRUE_STR) && !strncasecmp(payload, ZCOAP_TRUE_STR, len)) {
        *out = true;
        return 0;
    } else if (len >= strlen(ZCOAP_FALSE_STR) && !strncasecmp(payload, ZCOAP_FALSE_STR, len)) {
        *out = false;
        return 0;
    }
    // Truthiness strings were not found.  Fall back to attempting a numerical
    // text parse.
    int ival;
    int rc;
    if ((rc = coap_parse_req_int(ct, len, payload, &ival))) { // issues response and calls discard on our behalf if a parse error occurs
        return  rc;
    }
    *out = ival ? true : false;
    return 0;
}

/**
 * Utility CoAP getter printf function.  Allows generation of plain text CoAP
 * responses with printf-style semantics.
 *
 * @param req request to which to issue a response
 * @param fmt printf format string
 * @param ... printf arguments
 */
void coap_printf(coap_req_data_t * const req, const char *fmt, ...)
{
    va_list ap;
    size_t len;
    {
        va_start(ap, fmt);
        //Use snprintf to print to nothing but give us the length we need.
        //This lookse expenseive, but malloc is often worse in this case on many microcontrollers.
        len = ZCOAP_VSNPRINTF(NULL, 0, fmt, ap);
        va_end(ap);
    }
    {
#ifdef __GNUC__
       // We do not bounds-check for this stack buffer allocation.  Unlike
       // situatiions where the client is injecting data of variable length, we
       // have full control of what we print.  Thus we assume that what we are
       // printing is of reasonable length and safe to push on the stack.
        char buf[len + 1];
#else
        char *buf = ZCOAP_ALLOCA(len + 1);
        if (buf == NULL) {
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
            return;
        }
#endif /* __GNUC__ */
        va_start(ap, fmt);

        //Now actually write to the buffer, now that we know the desired length.
        len = ZCOAP_VSNPRINTF(buf, len + 1, fmt, ap);

        va_end(ap);
        coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_TEXT, len, buf);
#ifndef __GNUC__
        ZCOAP_ALLOCA_FREE(buf);
#endif /* __GNUC__ */
    }
}

/**
 * Respond to the client with an appropriately formatted payload.  If content
 * format is unspecified or specified as plain text, transmit as text.  If auto
 * content format is specified, transmit our native type in binary on the wire,
 * enclosing our native content format designator for proper interpretation by
 * the client.  If the client specifies a binary content format that is
 * different from our native type, but we can cast to the requested format and
 * still fully preserve our data, do so.  If the client specifies a content
 * format to which we cannot perform a lossless cast, return a content format
 * error.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_return_bool(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const bool val)
{
    coap_ct_t ct;
    coap_code_t coap_code;
    if ((coap_code = coap_get_accept_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, val ? ZCOAP_TRUE_STR : ZCOAP_FALSE_STR);
            break;
        case COAP_FMT_CBOR: {
            cbor_t cbor = { .type = CBOR_MAJOR_TYPE7, .add = val ? CBOR_ADD_INFO_TRUE : CBOR_ADD_INFO_FALSE };
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_CBOR, sizeof(cbor), &cbor);
            break;
        }
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NO_ACCEPT));
            break;
    }
}

/**
 * Respond to the client with an appropriately formatted payload.  If content
 * format is unspecified or specified as plain text, transmit as text.  If auto
 * content format is specified, transmit our native type in binary on the wire,
 * enclosing our native content format designator for proper interpretation by
 * the client.  If the client specifies a binary content format that is
 * different from our native type, but we can cast to the requested format and
 * still fully preserve our data, do so.  If the client specifies a content
 * format to which we cannot perform a lossless cast, return a content format
 * error.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_return_u16(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const char * const fmt, uint16_t val)
{
    coap_ct_t ct;
    coap_code_t coap_code;
    if ((coap_code = coap_get_accept_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_U16, val);
            break;
        case COAP_FMT_CBOR: {
            size_t len = sizeof(cbor_t) + sizeof(val);
#ifdef __GNUC__
            uint8_t buf[len];
#else
            uint8_t *buf = ZCOAP_ALLOCA(len);
            if (buf == NULL) {
                ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
                coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
                return;
            }
#endif /* __GNUC__ */
            cbor_t cbor = { .type = CBOR_MAJOR_TYPE_UNSIGNED, .add = CBOR_ADD_INFO_UINT16 };
            val = ZCOAP_HTONS(val);
            ZCOAP_MEMCPY(buf, &cbor, sizeof(cbor));
            ZCOAP_MEMCPY(buf + sizeof(cbor), &val, sizeof(val));
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_CBOR, len, buf);
#ifndef __GNUC__
            ZCOAP_ALLOCA_FREE(buf);
#endif /* __GNUC__ */
            break;
        }
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NO_ACCEPT));
            break;
    }
}

/**
 * Respond to the client with an appropriately formatted payload.  If content
 * format is unspecified or specified as plain text, transmit as text.  If auto
 * content format is specified, transmit our native type in binary on the wire,
 * enclosing our native content format designator for proper interpretation by
 * the client.  If the client specifies a binary content format that is
 * different from our native type, but we can cast to the requested format and
 * still fully preserve our data, do so.  If the client specifies a content
 * format to which we cannot perform a lossless cast, return a content format
 * error.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_return_u32(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const char * const fmt, uint32_t val)
{
    coap_ct_t ct;
    coap_code_t coap_code;
    if ((coap_code = coap_get_accept_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_U32, val);
            break;
        case COAP_FMT_CBOR: {
            size_t len = sizeof(cbor_t) + sizeof(val);
#ifdef __GNUC__
            uint8_t buf[len];
#else
            uint8_t *buf = ZCOAP_ALLOCA(len);
            if (buf == NULL) {
                ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
                coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
                return;
            }
#endif /* __GNUC__ */
            cbor_t cbor = { .type = CBOR_MAJOR_TYPE_UNSIGNED, .add = CBOR_ADD_INFO_UINT32 };
            val = ZCOAP_HTONL(val);
            ZCOAP_MEMCPY(buf, &cbor, sizeof(cbor));
            ZCOAP_MEMCPY(buf + sizeof(cbor), &val, sizeof(val));
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_CBOR, len, buf);
#ifndef __GNUC__
            ZCOAP_ALLOCA_FREE(buf);
#endif /* __GNUC__ */
            break;
        }
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NO_ACCEPT));
            break;
    }
}

/**
 * Respond to the client with an appropriately formatted payload.  If content
 * format is unspecified or specified as plain text, transmit as text.  If auto
 * content format is specified, transmit our native type in binary on the wire,
 * enclosing our native content format designator for proper interpretation by
 * the client.  If the client specifies a binary content format that is
 * different from our native type, but we can cast to the requested format and
 * still fully preserve our data, do so.  If the client specifies a content
 * format to which we cannot perform a lossless cast, return a content format
 * error.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_return_u64(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const char * const fmt, uint64_t val)
{
    coap_ct_t ct;
    coap_code_t coap_code;
    if ((coap_code = coap_get_accept_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_U64, val);
            break;
        case COAP_FMT_CBOR: {
            size_t len = sizeof(cbor_t) + sizeof(val);
#ifdef __GNUC__
            uint8_t buf[len];
#else
            uint8_t *buf = ZCOAP_ALLOCA(len);
            if (buf == NULL) {
                ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
                coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
                return;
            }
#endif /* __GNUC__ */
            cbor_t cbor = { .type = CBOR_MAJOR_TYPE_UNSIGNED, .add = CBOR_ADD_INFO_UINT64 };
            val = ZCOAP_HTONLL(val);
            ZCOAP_MEMCPY(buf, &cbor, sizeof(cbor));
            ZCOAP_MEMCPY(buf + sizeof(cbor), &val, sizeof(val));
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_CBOR, len, buf);
#ifndef __GNUC__
            ZCOAP_ALLOCA_FREE(buf);
#endif /* __GNUC__ */
            break;
        }
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NO_ACCEPT));
            break;
    }
}

/**
 * Respond to the client with an appropriately formatted payload.  If content
 * format is unspecified or specified as plain text, transmit as text.  If auto
 * content format is specified, transmit our native type in binary on the wire,
 * enclosing our native content format designator for proper interpretation by
 * the client.  If the client specifies a binary content format that is
 * different from our native type, but we can cast to the requested format and
 * still fully preserve our data, do so.  If the client specifies a content
 * format to which we cannot perform a lossless cast, return a content format
 * error.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_return_i16(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const char * const fmt, int16_t val)
{
    coap_ct_t ct;
    coap_code_t coap_code;
    if ((coap_code = coap_get_accept_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_I16, val);
            break;
        case COAP_FMT_CBOR: {
            size_t len = sizeof(cbor_t) + sizeof(val);
#ifdef __GNUC__
            uint8_t buf[len];
#else
            uint8_t *buf = ZCOAP_ALLOCA(len);
            if (buf == NULL) {
                ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
                coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
                return;
            }
#endif /* __GNUC__ */
            cbor_t cbor = { .type = val < 0 ? CBOR_MAJOR_TYPE_NEGATIVE : CBOR_MAJOR_TYPE_UNSIGNED, .add = CBOR_ADD_INFO_UINT16 };
            uint16_t _val = ZCOAP_HTONS(val < 0 ? -val : val);
            ZCOAP_MEMCPY(buf, &cbor, sizeof(cbor));
            ZCOAP_MEMCPY(buf + sizeof(cbor), &_val, sizeof(_val));
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_CBOR, len, buf);
#ifndef __GNUC__
            ZCOAP_ALLOCA_FREE(buf);
#endif /* __GNUC__ */
            break;
        }
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NO_ACCEPT));
            break;
    }
}

/**
 * Respond to the client with an appropriately formatted payload.  If content
 * format is unspecified or specified as plain text, transmit as text.  If auto
 * content format is specified, transmit our native type in binary on the wire,
 * enclosing our native content format designator for proper interpretation by
 * the client.  If the client specifies a binary content format that is
 * different from our native type, but we can cast to the requested format and
 * still fully preserve our data, do so.  If the client specifies a content
 * format to which we cannot perform a lossless cast, return a content format
 * error.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_return_i32(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const char * const fmt, int32_t val)
{
    coap_ct_t ct;
    coap_code_t coap_code;
    if ((coap_code = coap_get_accept_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_I32, val);
            break;
        case COAP_FMT_CBOR: {
            size_t len = sizeof(cbor_t) + sizeof(val);
#ifdef __GNUC__
            uint8_t buf[len];
#else
            uint8_t *buf = ZCOAP_ALLOCA(len);
            if (buf == NULL) {
                ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
                coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
                return;
            }
#endif /* __GNUC__ */
            cbor_t cbor = { .type = val < 0 ? CBOR_MAJOR_TYPE_NEGATIVE : CBOR_MAJOR_TYPE_UNSIGNED, .add = CBOR_ADD_INFO_UINT32 };
            uint32_t _val = ZCOAP_HTONL(val < 0 ? -val : val);
            ZCOAP_MEMCPY(buf, &cbor, sizeof(cbor));
            ZCOAP_MEMCPY(buf + sizeof(cbor), &_val, sizeof(_val));
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_CBOR, len, buf);
#ifndef __GNUC__
            ZCOAP_ALLOCA_FREE(buf);
#endif /* __GNUC__ */
            break;
        }
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NO_ACCEPT));
            break;
    }
}

/**
 * Respond to the client with an appropriately formatted payload.  If content
 * format is unspecified or specified as plain text, transmit as text.  If auto
 * content format is specified, transmit our native type in binary on the wire,
 * enclosing our native content format designator for proper interpretation by
 * the client.  If the client specifies a binary content format that is
 * different from our native type, but we can cast to the requested format and
 * still fully preserve our data, do so.  If the client specifies a content
 * format to which we cannot perform a lossless cast, return a content format
 * error.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_return_i64(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const char * const fmt, int64_t val)
{
    coap_ct_t ct;
    coap_code_t coap_code;
    if ((coap_code = coap_get_accept_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_I64, val);
            break;
        case COAP_FMT_CBOR: {
            size_t len = sizeof(cbor_t) + sizeof(val);
#ifdef __GNUC__
            uint8_t buf[len];
#else
            uint8_t *buf = ZCOAP_ALLOCA(len);
            if (buf == NULL) {
                ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
                coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
                return;
            }
#endif /* __GNUC__ */
            cbor_t cbor = { .type = val < 0 ? CBOR_MAJOR_TYPE_NEGATIVE : CBOR_MAJOR_TYPE_UNSIGNED, .add = CBOR_ADD_INFO_UINT64 };
            uint64_t _val = ZCOAP_HTONLL(val < 0 ? -val : val);
            ZCOAP_MEMCPY(buf, &cbor, sizeof(cbor));
            ZCOAP_MEMCPY(buf + sizeof(cbor), &_val, sizeof(_val));
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_CBOR, len, buf);
#ifndef __GNUC__
            ZCOAP_ALLOCA_FREE(buf);
#endif /* __GNUC__ */
            break;
        }
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NO_ACCEPT));
            break;
    }
}

/**
 * Respond to the client with an appropriately formatted payload.  If content
 * format is unspecified or specified as plain text, transmit as text.  If auto
 * content format is specified, transmit our native type in binary on the wire,
 * enclosing our native content format designator for proper interpretation by
 * the client.  If the client specifies a binary content format that is
 * different from our native type, but we can cast to the requested format and
 * still fully preserve our data, do so.  If the client specifies a content
 * format to which we cannot perform a lossless cast, return a content format
 * error.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_return_float(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const char * const fmt, float val)
{
    coap_ct_t ct;
    coap_code_t coap_code;
    if ((coap_code = coap_get_accept_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_FLOAT, (double)val); // %f means double - period, and whatever that is; do *not* use ZCOAP_DOUBLE macro here
            break;
        case COAP_FMT_CBOR: {
            size_t len = sizeof(cbor_t) + sizeof(val);
#ifdef __GNUC__
            uint8_t buf[len];
#else
            uint8_t *buf = ZCOAP_ALLOCA(len);
            if (buf == NULL) {
                ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
                coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
                return;
            }
#endif /* __GNUC__ */
            cbor_t cbor = { .type = val = CBOR_MAJOR_TYPE7, .add = CBOR_ADD_INFO_SINGLE };
            val = ZCOAP_HTONF(val);
            ZCOAP_MEMCPY(buf, &cbor, sizeof(cbor));
            ZCOAP_MEMCPY(buf + sizeof(cbor), &val, sizeof(val));
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_CBOR, len, buf);
#ifndef __GNUC__
            ZCOAP_ALLOCA_FREE(buf);
#endif /* __GNUC__ */
            break;
        }
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NO_ACCEPT));
            break;
    }
}

/**
 * Respond to the client with an appropriately formatted payload.  If content
 * format is unspecified or specified as plain text, transmit as text.  If auto
 * content format is specified, transmit our native type in binary on the wire,
 * enclosing our native content format designator for proper interpretation by
 * the client.  If the client specifies a binary content format that is
 * different from our native type, but we can cast to the requested format and
 * still fully preserve our data, do so.  If the client specifies a content
 * format to which we cannot perform a lossless cast, return a content format
 * error.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_return_double(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const char * const fmt, ZCOAP_DOUBLE val)
{
    coap_ct_t ct;
    coap_code_t coap_code;
    if ((coap_code = coap_get_accept_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_DOUBLE, (double)val); // %f means double - period, and whatever that is; do *not* use ZCOAP_DOUBLE macro here
            break;
        case COAP_FMT_CBOR: {
            size_t len = sizeof(cbor_t) + sizeof(val);
#ifdef __GNUC__
            uint8_t buf[len];
#else
            uint8_t *buf = ZCOAP_ALLOCA(len);
            if (buf == NULL) {
                ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
                coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
                return;
            }
#endif /* __GNUC__ */
            cbor_t cbor = { .type = CBOR_MAJOR_TYPE7, .add = CBOR_ADD_INFO_DOUBLE };
            val = ZCOAP_HTOND(val);
            ZCOAP_MEMCPY(buf, &cbor, sizeof(cbor));
            ZCOAP_MEMCPY(buf + sizeof(cbor), &val, sizeof(val));
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_CBOR, len, buf);
#ifndef __GNUC__
            ZCOAP_ALLOCA_FREE(buf);
#endif /* __GNUC__ */
            break;
        }
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NO_ACCEPT));
            break;
    }
}

/**
 * Utility GET handler for null-terminated C strings.
 *
 * If node->data is non-null, retrieve the value from this location.  Else
 * return an internal server error response.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_get_string( ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        const char *str = (const char *)node->data;
        size_t len = strlen(str);

#ifdef __GNUC__
       // We do not bounds-check for this stack buffer allocation.  Unlike
       // situatiions where the client is injecting data of variable length, we
       // have full control of what we print.  Thus we assume that what we are
       // printing is of reasonable length and safe to push on the stack.
        char buf[len + 1];
#else
        char *buf = ZCOAP_ALLOCA(len + 1);
        if (buf == NULL) {
            ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: ZCOAP_ALLOCA failed", __func__);
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
            return;
        }
#endif /* __GNUC__ */
        ZCOAP_MEMCPY(buf, str, len + 1);
        coap_printf(req, "%s", buf);
#ifndef __GNUC__
        ZCOAP_ALLOCA_FREE(buf);
#endif /* __GNUC__ */
    }
}

/**
 * Utility GET handler for booleans.
 *
 * If node->data is non-null, retrieve the value from this location.  Else
 * return an internal server error response.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_get_bool(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        bool val = *(volatile bool *)node->data;
        coap_return_bool(req, nopts, opts, val);
    }
}

/**
 * Utility GET handler for native-wdith unsigned integers.
 *
 * If node->data is non-null, retrieve the value from this location.  Else
 * return an internal server error response.
 *
 * node->fmt may be set to provide a non-default print format.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_get_u16(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        uint16_t val = *(volatile unsigned *)node->data;
        coap_return_u16(req, nopts, opts, node->fmt, val);
    }
}

/**
 * Utility GET handler for unsigned 32-bit integers.
 *
 * If node->data is non-null, retrieve the value from this location.  Else
 * return an internal server error response.
 *
 * node->fmt may be set to provide a non-default print format.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_get_u32(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        uint32_t val = *(volatile uint32_t *)node->data;
        coap_return_u32(req, nopts, opts, node->fmt, val);
    }
}

/**
 * Utility GET handler for unsigned 64-bit integers.
 *
 * If node->data is non-null, retrieve the value from this location.  Else
 * return an internal server error response.
 *
 * node->fmt may be set to provide a non-default print format.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_get_u64(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        uint64_t val = *(volatile uint64_t *)node->data;
        coap_return_u64(req, nopts, opts, node->fmt, val);
    }
}

/**
 * Utility GET handler for native-width integers.
 *
 * If node->data is non-null, retrieve the value from this location.  Else
 * return an internal server error response.
 *
 * node->fmt may be set to provide a non-default print format.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_get_i16(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        int16_t val = *(volatile int16_t *)node->data;
        coap_return_i16(req, nopts, opts, node->fmt, val);
    }
}

/**
 * Utility GET handler for 32-bit integers.
 *
 * If node->data is non-null, retrieve the value from this location.  Else
 * return an internal server error response.
 *
 * node->fmt may be set to provide a non-default print format.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_get_i32(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        uint32_t val = *(volatile uint32_t *)node->data;
        coap_return_i32(req, nopts, opts, node->fmt, val);
    }
}

/**
 * Utility GET handler for 64-bit integers.
 *
 * If node->data is non-null, retrieve the value from this location.  Else
 * return an internal server error response.
 *
 * node->fmt may be set to provide a non-default print format.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_get_i64(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        int64_t val = *(volatile int64_t *)node->data;
        coap_return_i64(req, nopts, opts, node->fmt, val);
    }
}

/**
 * Utility GET handler for single-precision floats.
 *
 * If node->data is non-null, retrieve the value from this location.  Else
 * return an internal server error response.
 *
 * node->fmt may be set to provide a non-default print format.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_get_float(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        float val = *(volatile float *)node->data;
        coap_return_float(req, nopts, opts, node->fmt, val);
    }
}

/**
 * Utility GET handler for double-precision floats.
 *
 * If node->data is non-null, retrieve the value from this location.  Else
 * return an internal server error response.
 *
 * node->fmt may be set to provide a non-default print format.
 *
 * @param req originating CoAP request
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_get_double(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_DOUBLE val = *(volatile ZCOAP_DOUBLE *)node->data;
        coap_return_double(req, nopts, opts, node->fmt, val);
    }
}

/**
 * Utility PUT handler for booleans.
 *
 * Parse the value in the request payload.  If parse is successful and the node
 * has a validate function, pass the value to this.  If the node has a non-null
 * data pointer and parse and validation have been successful, copy the value
 * to the node's data pointer.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_put_bool(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    bool val;
    coap_code_t code;
    if ((code = coap_parse_req_bool(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err = NULL;
    if (node->validate && (err = (*node->validate)(node, &val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        *(volatile bool *)(node->data) = val;
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
}

/**
 * Utility PUT handler for unsigned 16-bit integers.
 *
 * Parse the value in the request payload.  If parse is successful and the node
 * has a validate function, pass the value to this.  If the node has a non-null
 * data pointer and parse and validation have been successful, copy the value
 * to the node's data pointer.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_put_u16(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    uint16_t val;
    coap_code_t code;
    if ((code = coap_parse_req_u16(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err = NULL;
    if (node->validate && (err = (*node->validate)(node, &val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        *(volatile uint16_t *)(node->data) = val;
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
}

/**
 * Utility PUT handler for unsigned 32-bit integers.
 *
 * Parse the value in the request payload.  If parse is successful and the node
 * has a validate function, pass the value to this.  If the node has a non-null
 * data pointer and parse and validation have been successful, copy the value
 * to the node's data pointer.
 *
 * @param req originating CoAP request
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_put_u32(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    uint32_t val;
    coap_code_t code;
    if ((code = coap_parse_req_u32(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err;
    if (node->validate && (err = (*node->validate)(node, &val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        *(volatile uint32_t *)(node->data) = val;
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
}

/**
 * Utility PUT handler for unsigned 64-bit integers.
 *
 * Parse the value in the request payload.  If parse is successful and the node
 * has a validate function, pass the value to this.  If the node has a non-null
 * data pointer and parse and validation have been successful, copy the value
 * to the node's data pointer.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_put_u64(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    uint64_t val;
    coap_code_t code;
    if ((code = coap_parse_req_u64(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err;
    if (node->validate && (err = (*node->validate)(node, &val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        *(volatile uint64_t *)(node->data) = val;
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
}

/**
 * Utility PUT handler for integers.
 *
 * Parse the value in the request payload.  If parse is successful and the node
 * has a validate function, pass the value to this.  If the node has a non-null
 * data pointer and parse and validation have been successful, copy the value
 * to the node's data pointer.
 *
 * @param req originating CoAP request
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_put_i16(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    int16_t val;
    coap_code_t code;
    if ((code = coap_parse_req_i16(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err;
    if (node->validate && (err = (*node->validate)(node, &val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        *(volatile int16_t *)(node->data) = val;
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
}

/**
 * Utility PUT handler for 32-bit integers.
 *
 * Parse the value in the request payload.  If parse is successful and the node
 * has a validate function, pass the value to this.  If the node has a non-null
 * data pointer and parse and validation have been successful, copy the value
 * to the node's data pointer.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_put_i32(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    int32_t val;
    coap_code_t code;
    if ((code = coap_parse_req_i32(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err = NULL;
    if (node->validate && (err = (*node->validate)(node, &val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        *(volatile int32_t *)(node->data) = val;
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
}

/**
 * Utility PUT handler for 64-bit integers.
 *
 * Parse the value in the request payload.  If parse is successful and the node
 * has a validate function, pass the value to this.  If the node has a non-null
 * data pointer and parse and validation have been successful, copy the value
 * to the node's data pointer.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_put_i64(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    int64_t val;
    coap_code_t code;
    if ((code = coap_parse_req_i64(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err = NULL;
    if (node->validate && (err = (*node->validate)(node, &val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        *(volatile int64_t *)(node->data) = val;
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
}

/**
 * Utility PUT handler for single-precision floats.  Parse a single-precision
 * float from the client request payload.  If parse is successful and the node
 * has a validate function, pass the float to this.  If the node contains a
 * data pointer and parse and validation have been successful, copy the float\
 * to the node's data pointer.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_put_float(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    float val;
    coap_code_t code;
    if ((code = coap_parse_req_float(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err;
    if (node->validate && (err = (*node->validate)(node, &val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        *(volatile float *)(node->data) = val;
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
}

/**
 * Utility PUT handler for double-precision floats.  Parse a double-precision
 * float from the client request payload.  If parse is successful and the node
 * has a validate function, pass the double to this.  If the node contains a
 * data pointer and parse and validation have been successful, copy the double
 * to the node's data pointer.
 *
 * @param req originating CoAP request
 * @param nopts number of enclosed options
 * @param opts request options array
 * @param node server URI tree node
 */
void coap_put_double(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);
    ZCOAP_DOUBLE val;
    coap_code_t code;
    if ((code = coap_parse_req_double(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err;
    if (node->validate && (err = (*node->validate)(node, &val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        *(volatile ZCOAP_DOUBLE *)(node->data) = val;
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
}

/**
 * Count elements within the passed vector of content type designators.
 *
 * @param count (out) count of passed designators
 * @param ... one or more content type designators
 */
void count_ct(size_t * const count, ...)
{
    ZCOAP_ASSERT(count != NULL);
    va_list ap;
    va_start(ap, count);
    unsigned ct; // va_list element sizes will be platform-dependent; unsigned gets us the correct width
    while ((ct = va_arg(ap, unsigned)) != ZCOAP_FMT_SENTINEL) {
        ++*count;
    }
    va_end(ap);
}

/**
 * Extract elements from the passed vector of content type designators.
 *
 * @param cts (out) output write location for content type designators
 * @param ... one or more content type designators
 */
void extract_ct(coap_ct_t *cts, ...)
{
    coap_ct_t *cur = cts;
    va_list ap;
    va_start(ap, cts);
    unsigned ct; // va_list element sizes will be platform-dependent; unsigned gets us the correct width
    while ((ct = va_arg(ap, unsigned)) != ZCOAP_FMT_SENTINEL) {
        *cts = ct;
        ++cts;
    }
    va_end(ap);
}
