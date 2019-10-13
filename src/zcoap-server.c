/*
 * File:   zcoap.c
 * Author: Michael Sandstedt
 *
 * Created on March 31, 2018, 1:24 PM
 */

#include <errno.h>
#include <float.h>
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

#define RESPONSE_FMT_UINT "%u"
#define RESPONSE_FMT_INT "%d"
#define RESPONSE_FMT_ULONG "%lu"
#define RESPONSE_FMT_LONG "%ld"
#define RESPONSE_FMT_ULLONG "0x%llX" /* 64-biit decimal printing can be truncated by znsprintf; hex printing works though */
#define RESPONSE_FMT_LLONG RESPONSE_FMT_ULLONG
#define RESPONSE_FMT_FLOAT "%.8g"
#if (__DBL_MANT_DIG__ != 53 && __LDBL_MANT_DIG__ == 53)
#define RESPONSE_FMT_DOUBLE "%.8Lg"
#define ZCOAP_DOUBLE long double
#elif (__DBL_MANT_DIG__ != 53)
#error unable find a native 64-bit type for the zcoap double!
#else
#define RESPONSE_FMT_DOUBLE "%.8g"
#endif

#define RESPONSE_FMT_U16 RESPONSE_FMT_UINT
#define RESPONSE_FMT_I16 RESPONSE_FMT_INT
#if UINT32_MAX == UINT_MAX
#define RESPONSE_FMT_U32 RESPONSE_FMT_UINT
#define RESPONSE_FMT_I32 RESPONSE_FMT_INT
#elif UINT32_MAX == ULONG_MAX
#define RESPONSE_FMT_U32 RESPONSE_FMT_ULONG
#define RESPONSE_FMT_I32 RESPONSE_FMT_LONG
#else
#error cannot determine appropriate format specifiers for 32-bit integers!
#endif
#if UINT64_MAX == ULONG_MAX
#define RESPONSE_FMT_U64 RESPONSE_FMT_ULONG
#define RESPONSE_FMT_I64 RESPONSE_FMT_LONG
#elif UINT64_MAX == ULLONG_MAX
#define RESPONSE_FMT_U64 RESPONSE_FMT_ULLONG
#define RESPONSE_FMT_I64 RESPONSE_FMT_LLONG
#else
#error cannot determine appropriate format specifiers for 64-bit integers!
#endif

/**
 * Perform a quick runtime arithmetic check to determine whether the host
 * environment is little endian.  If it is, return true.  Else, return false.
 *
 * @return true if host environment is little endian, else false
 */
static bool host_is_little_endian(void)
{
    if (ZCOAP_HTONS(42) != 42) {
        return true;
    } else {
        return false;
    }
}

/**
 * Convert a 64-bit integer to network byte order.
 *
 * @param hostllong 64-bit integer in host byte order
 * @param 64-bit integer in network byte order
 */
static uint64_t __attribute__((const)) ZCOAP_HTONLL(uint64_t hostllong)
{
    if (!host_is_little_endian) {
        return hostllong; // no conversion necessary
    }
    uint64_t netllong;
    uint8_t *p = (uint8_t *)&hostllong;
    uint8_t *q = (uint8_t *)&netllong;
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
 * Convert a single-precision float to network byte order.
 *
 * @param hostfloat single-precision IEEE-754 float in host byte order
 * @param single-precision IEEE-754 float in network byte order
 */
static float __attribute__((const)) ZCOAP_HTONF(float hostfloat)
{
    if (!host_is_little_endian) {
        return hostfloat; // no conversion necessary
    }
    float netfloat;
    uint8_t *p = (uint8_t *)&hostfloat;
    uint8_t *q = (uint8_t *)&netfloat;
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
static ZCOAP_DOUBLE __attribute__((const)) ZCOAP_HTOND(ZCOAP_DOUBLE hostdouble)
{
    if (!host_is_little_endian) {
        return hostdouble; // no conversion necessary
    }
    ZCOAP_DOUBLE netdouble;
    uint8_t *p = (uint8_t *)&hostdouble;
    uint8_t *q = (uint8_t *)&netdouble;
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
#define ZCOAP_NTOHLL ZCOAP_HTONLL
#define ZCOAP_NTOHF ZCOAP_HTONF
#define ZCOAP_NTOHD ZCOAP_HTOND

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
static bool __attribute__((pure)) href_match(const char *name, const href_filter_t *href_filter)
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

// Copy of coap_handler_t signature, but with __attribute__((nonnull (1, 2)))
// removed.  This allows passage of NULL, NULL when we wish to access handlers'
// alternate function: extraction of node content type.
typedef void (*ct_extractor)(ZCOAP_METHOD_SIGNATURE);

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
static void SNPRINTF(size_t *total, char **buf, size_t *remain, const char *fmt, ...)
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
 * Invoke a node's methods in 'ct_extractor' mode, passing a ct_mask for each
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
static void print_ct(const coap_node_t * const node, size_t *len, char **buf, size_t *remain)
{
    ct_mask_t mask = {{ 0 }};
    if (node->GET) {
        (*(ct_extractor)node->GET)(node, NULL, 0, NULL, 0, 0, NULL, &mask);
        if (mask.literal_set) {
            // Alternate literal encoding; mask is not a mask at all, but contains
            // a single content type literal in the lower byte.
            SNPRINTF(len, buf, remain, ";ct=%u", mask.ct_literal);
            ZCOAP_MEMSET(&mask, 0, sizeof(mask));
        }
    }
    if (node->PUT) {
        (*(ct_extractor)node->PUT)(node, NULL, 0, NULL, 0, 0, NULL, &mask);
        if (mask.literal_set) {
            // Alternate literal encoding; mask is not a mask at all, but contains
            // a single content type literal in the lower byte.
            SNPRINTF(len, buf, remain, ";ct=%u", mask.ct_literal);
            ZCOAP_MEMSET(&mask, 0, sizeof(mask));
        }
    }
    if (node->POST) {
        (*(ct_extractor)node->POST)(node, NULL, 0, NULL, 0, 0, NULL, &mask);
        if (mask.literal_set) {
            // Alternate literal encoding; mask is not a mask at all, but contains
            // a single content type literal in the lower byte.
            SNPRINTF(len, buf, remain, ";ct=%u", mask.ct_literal);
            ZCOAP_MEMSET(&mask, 0, sizeof(mask));
        }
    }
    if (node->DELETE) {
        (*(ct_extractor)node->DELETE)(node, NULL, 0, NULL, 0, 0, NULL, &mask);
        if (mask.literal_set) {
            // Alternate literal encoding; mask is not a mask at all, but contains
            // a single content type literal in the lower byte.
            SNPRINTF(len, buf, remain, ";ct=%u", mask.ct_literal);
            ZCOAP_MEMSET(&mask, 0, sizeof(mask));
        }
    }
    if (mask.ct_text) {
        SNPRINTF(len, buf, remain, ";ct=%u", COAP_FMT_TEXT);
    }
    if (mask.ct_link) {
        SNPRINTF(len, buf, remain, ";ct=%u", COAP_FMT_LINK);
    }
    if (mask.ct_xml) {
        SNPRINTF(len, buf, remain, ";ct=%u", COAP_FMT_XML);
    }
    if (mask.ct_ostream) {
        SNPRINTF(len, buf, remain, ";ct=%u", COAP_FMT_STREAM);
    }
    if (mask.ct_exi) {
        SNPRINTF(len, buf, remain, ";ct=%u", COAP_FMT_EXI);
    }
    if (mask.ct_json) {
        SNPRINTF(len, buf, remain, ";ct=%u", COAP_FMT_JSON);
    }
    #ifdef ZCOAP_EXTENSIONS
    if (mask.ct_bool) {
        SNPRINTF(len, buf, remain, ";ct=%u", ZCOAP_FMT_BOOL);
    }
    if (mask.ct_u16) {
        SNPRINTF(len, buf, remain, ";ct=%u", ZCOAP_FMT_U16);
    }
    if (mask.ct_u32) {
        SNPRINTF(len, buf, remain, ";ct=%u", ZCOAP_FMT_U32);
    }
    if (mask.ct_u64) {
        SNPRINTF(len, buf, remain, ";ct=%u", ZCOAP_FMT_U64);
    }
    if (mask.ct_i16) {
        SNPRINTF(len, buf, remain, ";ct=%u", ZCOAP_FMT_I16);
    }
    if (mask.ct_i32) {
        SNPRINTF(len, buf, remain, ";ct=%u", ZCOAP_FMT_I32);
    }
    if (mask.ct_i64) {
        SNPRINTF(len, buf, remain, ";ct=%u", ZCOAP_FMT_I64);
    }
    if (mask.ct_float) {
        SNPRINTF(len, buf, remain, ";ct=%u", ZCOAP_FMT_FLOAT);
    }
    if (mask.ct_double) {
        SNPRINTF(len, buf, remain, ";ct=%u", ZCOAP_FMT_DOUBLE);
    }
    #endif /* ZCOAP_EXTENSIONS */
}

/**
 * Recurse URI tree iterator for performing a depth-first walk of the URI tree
 * and dumping an RFC6690-compliant .well-known/core response.
 *
 * @param pwd present working directory; the path preceding node
 * @param node current iteration root node
 * @param href_filter filter against which to match as in a .well-known/core?href= filtered query
 * @param parent_href_match sticky flag to tell us if a parent path segment matched href; if so, we inherit match
 * @param len (out) number of characters that would have been printed had remain been large enough
 * @param buf buffer to print into
 * @param remain number of bytes available in buf
 */
static void iter_coap_tree(char *pwd, const coap_node_t * const node, const href_filter_t *href_filter, const bool parent_href_match, size_t *len, char **buf, size_t *remain)
{
    if (node->children) {
        for (const coap_node_t * const *c = node->children; *c != NULL; ++c) {
            if ((*c)->name == NULL) {
                continue; // suppress output of unnamed elements
            } else if (href_filter->str) {
                if (!parent_href_match && !href_match((*c)->name, href_filter)) {
                    continue;
                }
            } else if ((*c)->name[0] == '.' || (*c)->hidden) {
                continue; // suppress output of hidden elements
            } else if (!(*c)->GET && !(*c)->PUT && !(*c)->POST && !(*c)->DELETE) {
                continue; // suppress output of nodes with no methods
            }
            SNPRINTF(len, buf, remain, "<%s%s>", pwd, (*c)->name);
            print_ct(*c, len, buf, remain);
            SNPRINTF(len, buf, remain, ",");
        }
    }
    if (node->gens) {
        for (const coap_gen_t *g = node->gens; *g != NULL; ++g) {
            coap_meta_t iterator = 0;
            while (1) {
                coap_node_t dynamic_node = { .parent = node };
                if ((**g)(&iterator, &dynamic_node)) {
                    break;
                }
                if (dynamic_node.name == NULL) {
                    continue; // suppress output of unnamed elements
                } else if (href_filter->str) {
                    if (!parent_href_match && !href_match(dynamic_node.name, href_filter)) {
                        continue;
                    }
                } else if (dynamic_node.name[0] == '.' || dynamic_node.hidden) {
                    continue; // suppress output of hidden elements
                } else if (!dynamic_node.GET && !dynamic_node.PUT && !dynamic_node.POST && !dynamic_node.DELETE) {
                    continue; // suppress output of nodes with no methods
                }
                SNPRINTF(len, buf, remain, "<%s%s>", pwd, dynamic_node.name);
                print_ct(&dynamic_node, len, buf, remain);
                SNPRINTF(len, buf, remain, ",");
            }
        }
    }
    if (node->children) {
        size_t pwdlen = strlen(pwd);
        for (const coap_node_t * const *c = node->children; *c != NULL; ++c) {
            if ((*c)->name == NULL) {
                continue; // suppress output of unnamed elements
            } else if (!href_filter->str && ((*c)->name[0] == '.' || (*c)->hidden)) {
                continue; // suppress output of hidden elements
            }
            size_t cplen = strlen((*c)->name);
            char cpbuf[pwdlen + cplen + 1 /* '/' */ + 1 /* '\0' */];
            ZCOAP_MEMCPY(cpbuf, pwd, pwdlen);
            ZCOAP_MEMCPY(cpbuf + pwdlen, (*c)->name, cplen);
            cpbuf[pwdlen + cplen] = '/';
            cpbuf[pwdlen + cplen + 1] = '\0';
            iter_coap_tree(cpbuf, *c, href_filter, parent_href_match || href_match((*c)->name, href_filter), len, buf, remain);
        }
    }
    if (node->gens) {
        size_t pwdlen = strlen(pwd);
        for (const coap_gen_t *g = node->gens; *g != NULL; ++g) {
            coap_meta_t iterator = 0;
            while (1) {
                coap_node_t dynamic_node = { .parent = node };
                if ((**g)(&iterator, &dynamic_node)) {
                    break;
                }
                if (dynamic_node.name == NULL) {
                    continue; // suppress output of unnamed elements
                } else if (!href_filter->str && (dynamic_node.name[0] == '.' || dynamic_node.hidden)) {
                    continue; // suppress output of hidden elements
                }
                size_t cplen = strlen(dynamic_node.name);
                char cpbuf[pwdlen + cplen + 1 /* '/' */ + 1 /* '\0' */];
                ZCOAP_MEMCPY(cpbuf, pwd, pwdlen);
                ZCOAP_MEMCPY(cpbuf + pwdlen, dynamic_node.name, cplen);
                cpbuf[pwdlen + cplen] = '/';
                cpbuf[pwdlen + cplen + 1] = '\0';
                iter_coap_tree(cpbuf, &dynamic_node, href_filter, parent_href_match || href_match(dynamic_node.name, href_filter), len, buf, remain);
            }
        }
    }
}

/**
 * Recursively call iter_coap_tree for the depth-first URI path dump of
 * .well-known/core
 *
 * @param buf buf to print into
 * @param number of bytes available in buf
 * @param root root node of tree
 * @param href_filter filter for matching path segments
 * @return number of characters, excluding '\0', that would have been printed had remain been large enough
 */
static size_t snprintf_coap_tree(char *buf, size_t remain, const coap_node_t *root, const href_filter_t *href_filter)
{
    char *root_pwd = "/";
    size_t len = 0;
    iter_coap_tree(root_pwd, root, href_filter, href_match("", href_filter), &len, &buf, &remain);
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
static int opt_cmp(const void *a, const void *b)
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
 * GET request handler for .well-known/core.  Perform a depth-first search of
 * the CoAP URI tree and print all URIs as prescribed by RFC-6690.
 *
 * Finds the root node '/' by relative reference from ./core, i.e.:
 *    /.well-known/core/../../
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
    if (node->parent == NULL || node->parent->parent == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    const coap_node_t *root = node->parent->parent; // locate root at /.well-known/core/../../
    const href_filter_t href_filter = get_href_filter(nopts, opts);
    size_t wkn_len = snprintf_coap_tree(NULL, 0, root, &href_filter);
    char *buf = ZCOAP_MALLOC(wkn_len + 1);
    if (buf == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    wkn_len = snprintf_coap_tree(buf, wkn_len + 1, root, &href_filter);
    if (wkn_len && buf[wkn_len - 1] == ',') {
        --wkn_len;
    }
    coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_LINK, wkn_len, buf);
    ZCOAP_FREE(buf);
}
static const coap_node_t core_uri = { .name = "core", .GET = &coap_get_wellknown_core };
static const coap_node_t *wellknown_children[] = { &core_uri, NULL };

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
 * server is one of the *very* few (actually, the only one this writer knows of)
 * that provides content-type discovery in the .well-known/core interface.
 * Big value!
 */
const coap_node_t wellknown_uri = { .name = ".well-known", .children = wellknown_children };

/**
 * Stable comparison for options.  Compares both option number (first) and
 * current memory address (second) to achieve stable sort by preserving relative
 * order for like-numbered options
 *
 * @param a option
 * @param b option
 * @return 1 for a>b, 0 for a==b, -1 for a<b
 */
static int opt_scmp(const void *a, const void *b)
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
static void stable_sort_opts(size_t nopts, const coap_opt_t opts[], const coap_opt_t *sorted[])
{
    // STABLE sort; caller must allocate sorted.
    if (nopts == 0) {
        return;
    }
    for (size_t i = 0; i < nopts; ++i) {
        sorted[i] = &opts[i]; // initialize pointers
    }
    qsort((void *)sorted, nopts, sizeof(sorted[0]), &opt_scmp);
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
static coap_code_t *stuff_option(uint32_t *acc, uint16_t optnum, uint16_t optlen, const void *opt, uint8_t *buf)
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
static coap_code_t *stuff_options(uint8_t *buf, size_t nopts, const coap_opt_t opts[])
{
    // As awkward as it is, we must pre-sort our options in order to build a
    // CoAP options payload.  Option-number-delta is unsigned, so option numbers
    // must be monotonically increasing as we traverse the packet.
    //
    // To ensure robustness, this function preforms the sort itself.
    const coap_opt_t *sorted[nopts]; // allocate temp pointer array on the stack
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
static size_t opt_sec_len(size_t nopts, const coap_opt_t opts[])
{
    // As awkward as it is, we must pre-sort our options in order to determine
    // the length of the CoAP options payload.  Option-number-delta is unsigned,
    // so option numbers must be monotonically increasing as we traverse the
    // packet.
    // To ensure robustness, this function preforms the sort itself.
    const coap_opt_t *sorted[nopts]; // allocate temp pointer array on the stack
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
static void __attribute__((nonnull (1))) coap_discard(coap_req_data_t * const req)
{
    if (req == NULL) {
        return;
    }
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
void __attribute__((nonnull (1))) coap_ack(coap_req_data_t * const req)
{
    if (   req == NULL
        || req->msg == NULL
        || req->len < sizeof(coap_msg_t)
        || req->responder == NULL) {
        return;
    }
    if (req->msg->type == COAP_TYPE_NON_CONFIRMABLE) {
        return; // no ACK needed
    } else if (req->msg->type != COAP_TYPE_CONFIRMABLE) {
        return; // should never land here!
    }
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
void __attribute__((nonnull (1))) coap_rsp(coap_req_data_t * const req, const coap_code_t code, const size_t nopts, const coap_opt_t opts[], const size_t pl_len, const void * const payload)
{
    // Check arguments.
    if (   req == NULL
        || req->msg == NULL
        || req->len < sizeof(coap_msg_t)
        || req->len < sizeof(coap_msg_t) + req->msg->tkl
        || req->msg->tkl > COAP_MAX_TKL
        || req->responder == NULL) {
        coap_discard(req);
        return;
    }
    // Determine how big our response PDU will be.
    size_t alen = sizeof(coap_msg_t) + req->msg->tkl;
    alen += opt_sec_len(nopts, opts);
    if (pl_len && payload) {
        alen += COAP_PL_MARKER_SIZE; // for payload marker
        alen += pl_len; // for the payload itself
    }
    // Allocate our response PDU.
    coap_msg_t *rsp;
    if ((rsp = ZCOAP_ALLOCA(alen)) == NULL) {
        coap_discard(req);
        return;
    }
    // Copy message header and token.
    ZCOAP_MEMCPY(rsp, req->msg, sizeof(coap_msg_t) + req->msg->tkl);
    if (req->msg->type == COAP_TYPE_CONFIRMABLE && !req->state.acked) {
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
    uint8_t *pl_ptr = stuff_options(opt_ptr, nopts, opts);
    if (pl_len && payload) {
        *pl_ptr = COAP_PAYLOAD_MARKER;
        ++pl_ptr;
        ZCOAP_MEMCPY(pl_ptr, payload, pl_len);
    }
    // Transmit the response!
    (*req->responder)(req, alen, rsp);
    // Free our memory and cleanup.
    ZCOAP_ALLOCA_FREE(rsp);
    coap_discard(req);
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
void __attribute__((nonnull (1))) coap_content_rsp(coap_req_data_t * const req, const coap_code_t code, coap_ct_t ct, const size_t pl_len, const void * const payload)
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
void __attribute__((nonnull (1))) coap_detail_rsp(coap_req_data_t * const req, const coap_code_t code, const char * const detail)
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
void __attribute__((nonnull (1))) coap_status_rsp(coap_req_data_t * const req, const coap_code_t code)
{
    return coap_rsp(req, code, 0, NULL, 0, NULL);
}

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
static coap_code_t __attribute__((nonnull (1, 2))) coap_count_opts(coap_req_data_t * const req, size_t * const nopts)
{
    if (req == NULL || nopts == NULL) {
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
    if (*nopts > ZCOAP_MAX_PAYLOAD_OPTS) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }  else {
        return 0;
    }
}

/**
 * Parse the options from the passed request.
 *
 * @param req CoAP request from which to parse options
 * @param nopts maximum number of options to parse
 * @param opts (out) write location for parsed options
 * @return 0 on success, else a CoAP error code
 */
static coap_code_t __attribute__((nonnull (1, 3))) coap_get_opts(coap_req_data_t * const req, const size_t nopts, coap_msg_opt_t * const opts)
{
    if (req == NULL || opts == NULL) {
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
    const uint8_t *ptr = COAP_OPTS(req->msg);
    uint32_t opt_num = 0;
    for (size_t i = 0; i < nopts; ++i) {
        if (!remain || *ptr == COAP_PAYLOAD_MARKER) {
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
 * Get a CoAP content format option from a CoAP request.  Parses req for its
 * options if caller passes opts == NULL.
 *
 * @param req request to search for content format option
 * @param nopts number of options in the request
 * @param opts parsed request options, or null if not available
 * @param ct (out) written to content format option value if a content format option was found
 * @return 0 on success, else CoAP error code; note that content format option not found is NOT an error; in such a case, content_fmt remains unwritten
 */
coap_code_t __attribute__((nonnull (1, 4))) coap_get_content_type(coap_req_data_t * const req, size_t nopts, const coap_msg_opt_t opts[], coap_ct_t * const ct)
{
    if (ct == NULL) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (opts == NULL && req == NULL) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    *ct = ZCOAP_FMT_NONE;
    coap_code_t rc;
    if (opts == NULL && (rc = coap_count_opts(req, &nopts))) {
        return rc;
    }
    if (nopts == 0) {
        return 0;
    }
    coap_msg_opt_t *ct_opt = NULL;
    // In the bsearch, we will find *an* occurrence of a content-format option.
    // If the requesting agent has enclosed more than one, that's a protocol
    // violation on their part and not our problem.
    if (opts == NULL) {
        coap_msg_opt_t lopts[nopts];
        if ((rc = coap_get_opts(req, nopts, lopts))) {
            return rc;
        }
        const coap_msg_opt_t key = { .num = COAP_OPT_CONTENT_FMT };
        ct_opt = bsearch(&key, lopts, nopts, sizeof(lopts[0]), &opt_cmp);
    } else {
        const coap_msg_opt_t key = { .num = COAP_OPT_CONTENT_FMT };
        ct_opt = bsearch(&key, opts, nopts, sizeof(opts[0]), &opt_cmp);
    }
    if (ct_opt == NULL) {
        // No content format option found.
        return 0;
    }
    if (!ct_opt->len) {
        // Per RFC 7252, a zero-length option value field is simply
        // empty.  And this is legal for the content format
        // designator.  We'll interpret this as unspecified / don't
        // care.  To the caller, this will be equivalent to the case
        // where no content format option was included at all.
        return 0;
    }
    if (ct_opt->len > sizeof(coap_ct_t)) {
        // Per RFC6690, content format option value should be 65535 or less.
        // We will therefore only accept 0, 1 and 2-byte value fields.  We
        // suppose a client could pack a 2-byte big-endian content type into
        // *more* bytes, but this seems an odd abuse of the wire format.
        // Reject!
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
    } else if (ct_opt->len == sizeof(coap_ct_t)) {
        uint16_t netshort;
        ZCOAP_MEMCPY(&netshort, ct_opt->val, sizeof(netshort));
        *ct = ZCOAP_NTOHS(netshort);
    } else {
        *ct = *(uint8_t *)ct_opt->val;
    }
    switch (*ct) {
        case COAP_FMT_TEXT:
        case COAP_FMT_LINK:
        case COAP_FMT_XML:
        case COAP_FMT_STREAM:
        case COAP_FMT_EXI:
        case COAP_FMT_JSON:
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_AUTO:
        case ZCOAP_FMT_BOOL:
        case ZCOAP_FMT_U16:
        case ZCOAP_FMT_I16:
        case ZCOAP_FMT_U32:
        case ZCOAP_FMT_I32:
        case ZCOAP_FMT_U64:
        case ZCOAP_FMT_I64:
        case ZCOAP_FMT_FLOAT:
        case ZCOAP_FMT_DOUBLE:
        #endif /* ZCOAP_EXTENSIONS */
            break;
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    return 0;
}

/**
 * Get the payload from the passed request.
 *
 * @param req CoAP request to parse
 * @param len (out) payload length
 * @param payload (out) payload
 * @return 0 on success, else CoAP error code
 */
coap_code_t __attribute__((nonnull (1, 2, 3))) coap_get_payload(coap_req_data_t * const req, size_t * const len, const void **payload)
{
    if (req == NULL || len == NULL || payload == NULL) {
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
#define EXTRACT_CONTENT_TYPE_AND_PAYLOAD(_req) ({\
    coap_code_t _rc;\
    if ((_rc = coap_get_content_type(req, nopts, opts, &ct))) {\
        return _rc;\
    }\
    if ((_rc = coap_get_payload(req, &len, &payload))) {\
        return _rc;\
    }\
})

/**
 * Process a CoAP request and dispatch to the appropriate handler based upon
 * message class and request method.
 *
 * @param req CoAP request to process
 * @param nopts number of options in the request
 * @param opts parsed request options, or NULL if unavailable to the caller
 * @param node server tree node matching request URI
 * @return 0 on success, else a CoAP error code
 */
static coap_code_t __attribute__((nonnull (1, 4))) process_req_uri(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], const coap_node_t * const node)
{
    // On successful handler dispatch, return 0.  In such a case, the handler
    // becomes responsible for responding to the client and calling discard.
    //
    // On failure, return an appropriate error code.
    coap_ct_t ct;
    size_t len;
    const void *payload;
    switch (req->msg->code.code_class) {
        case COAP_REQ:
            switch (req->msg->code.code_detail) {
                case COAP_REQ_METHOD_GET:
                    if (node->GET) {
                        EXTRACT_CONTENT_TYPE_AND_PAYLOAD(req);
                        #ifdef ZCOAP_DEBUG
                        ZCOAP_DEBUG("%s: servicing GET for path '%s'", __func__, node->name);
                        #endif
                        (*node->GET)(node, req, nopts, opts, ct, len, payload, NULL);
                        return 0;
                    } else {
                        #ifdef ZCOAP_DEBUG
                        ZCOAP_DEBUG("%s: GET method unsupported for path '%s'", __func__, node->name);
                        #endif
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED);
                    }
                case COAP_REQ_METHOD_PUT:
                    if (node->PUT) {
                        EXTRACT_CONTENT_TYPE_AND_PAYLOAD(req);
                        #ifdef ZCOAP_DEBUG
                        ZCOAP_DEBUG(TX_GLOBAL, "%s: servicing PUT for path '%s'", __func__, node->name);
                        #endif
                        (*node->PUT)(node, req, nopts, opts, ct, len, payload, NULL);
                        return 0;
                    } else {
                        #ifdef ZCOAP_DEBUG
                        ZCOAP_DEBUG("%s: PUT method unsupported for path '%s'", __func__, node->name);
                        #endif
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED);
                    }
                case COAP_REQ_METHOD_POST:
                    if (node->POST) {
                        EXTRACT_CONTENT_TYPE_AND_PAYLOAD(req);
                        #ifdef ZCOAP_DEBUG
                        ZCOAP_DEBUG("%s: servicing POST for path '%s'", __func__, node->name);
                        #endif
                        (*node->POST)(node, req, nopts, opts, ct, len, payload, NULL);
                        return 0;
                    } else {
                        #ifdef ZCOAP_DEBUG
                        ZCOAP_DEBUG("%s: POST method unsupported for path '%s'", __func__, node->name);
                        #endif
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED);
                    }
                case COAP_REQ_METHOD_DELETE:
                    if (node->DELETE) {
                        EXTRACT_CONTENT_TYPE_AND_PAYLOAD(req);
                        #ifdef ZCOAP_DEBUG
                        ZCOAP_DEBUG("%s: servicing DELETE for path '%s'", __func__, node->name);
                        #endif
                        (*node->DELETE)(node, req, nopts, opts, ct, len, payload, NULL);
                        return 0;
                    } else {
                        #ifdef ZCOAP_DEBUG
                        ZCOAP_DEBUG("%s: DELETE method unsupported for path '%s'", __func__, node->name);
                        #endif
                        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED);
                    }
                default:
                    #ifdef ZCOAP_DEBUG
                    ZCOAP_DEBUG("%s: unable to service method %u for path '%s'", __func__, req->msg->code.code_detail, node->name);
                    #endif
                    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED);
            }
        default:
            #ifdef ZCOAP_DEBUG
            ZCOAP_DEBUG("%s: ignoring message with class %u and path option '%s'", __func__, req->msg->code.code_class, node->name);
            #endif
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
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
 * URI tree children are stored in null-terminated arrays.  Count the passed
 * node's children.
 *
 * @param node URI tree node for which to count children
 * @return number of children found
 */
static size_t coap_count_children(const coap_node_t * const node)
{
    size_t count = 0;
    const coap_node_t **child = node->children;
    while (child && *child) {
        ++count;
        ++child;
    }
    return count;
}

// Forward declaration.
static coap_code_t __attribute__((nonnull (1, 3, 5, 6))) iter_req_uri(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], size_t npath_opts, const coap_msg_opt_t *path_opts, const coap_node_t * const path);

/**
 * Iterate through the tree starting at path to find a match
 * to the path as defined by the passed path_opts array.
 *
 * @param req CoAP request to handle
 * @param nopts number of options enclosed in req
 * @param opts array of option pointers into req
 * @param npath_opts number of path options enclosed in req
 * @param path_opts array of path option pointers into req
 * @param path node defining the top of a tree against which request path should be matched
 */
static coap_code_t __attribute__((nonnull (1, 3, 5, 6))) iter_req_uri(coap_req_data_t * const req, const size_t nopts, const coap_msg_opt_t opts[], size_t npath_opts, const coap_msg_opt_t *path_opts, const coap_node_t * const path)
{
    size_t count = coap_count_children(path);
    const coap_msg_opt_t *opt = &path_opts[0];
    if (count && opt->len < ZCOAP_MAX_BUF_SIZE) { // skip path segments that are too large
        char keyname[opt->len + 1];
        ZCOAP_MEMCPY(keyname, opt->val, opt->len);
        keyname[opt->len] = '\0';
        const coap_node_t bsearchkey = { .name = keyname };
        const coap_node_t *keyptr = &bsearchkey;
        const coap_node_t **c = bsearch(&keyptr, path->children, count, sizeof(path->children[0]), coap_node_cmp);
        if (c) {
            coap_node_t node;
            ZCOAP_MEMCPY(&node, *c, sizeof(node));
            node.parent = path;
            --npath_opts;
            if (!npath_opts) { // end of options
                return process_req_uri(req, nopts, opts, &node);
            } else { // continue searching; we have more path segments to compare
                ++path_opts;
                return iter_req_uri(req, nopts, opts, npath_opts, path_opts, &node);
            }
        }
    }
    for (const coap_gen_t *g = path->gens; g != NULL && *g != NULL; ++g) {
        coap_meta_t iterator = 0;
        while (1) {
            coap_node_t dynamic_node = { .parent = path };
            if ((**g)(&iterator, &dynamic_node)) {
                break;
            }
            if (   !strncmp((char *)opt->val, dynamic_node.name, opt->len)
                && strlen(dynamic_node.name) == opt->len) {
                --npath_opts;
                if (!npath_opts) { // end of options
                    return process_req_uri(req, nopts, opts, &dynamic_node);
                } else { // continue searching; we have more path segments to compare
                    ++path_opts;
                    return iter_req_uri(req, nopts, opts, npath_opts, path_opts, &dynamic_node);
                }
            }
        }
    }
    if (path && path->wildcard) { // if no children matched, but the parent has wildcard set, match to the parent
        return process_req_uri(req, nopts, opts, path);
    }
    // If we ever get here, it means the client specified a path
    // segment that we were unable to resolve.  Hence, 404.
    #ifdef ZCOAP_DEBUG
    {
        char buf[opt->len + 1];
        ZCOAP_MEMCPY(buf, opt->val, opt->len);
        buf[opt->len] = '\0';
        ZCOAP_DEBUG("%s: unable to resolve request path '%s'!", __func__, buf);
    }
    #endif
    return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_NOT_FOUND);
}

/**
 * Inject a CoAP request into our CoAP server and process it through the URI
 * tree starting at the passed root node.
 *
 * @param req CoAP request to inject into the server
 * @param root root of the URI tree that should be used to process the request
 */
static void __attribute__((nonnull (1, 1))) inject_coap_req(coap_req_data_t * const req, const coap_node_t * const root)
{
    size_t nopts;
    coap_code_t rc;
    // Count options.
    if (coap_count_opts(req, &nopts)) {
        return;
    }
    // No options means no path, which implies match to the root node.
    // We have this check here because bsearch can choke on an empty array.
    if (nopts == 0) {
        process_req_uri(req, nopts, NULL, root);
    }
    // Parse options array.
    coap_msg_opt_t opts[nopts];
    if (coap_get_opts(req, nopts, opts)) {
        return;
    }
    // Find *an* occurrence of a path option (perhaps not the first).
    const coap_msg_opt_t key = { .num = COAP_OPT_PATH };
    coap_msg_opt_t *a_path_opt = bsearch(&key, opts, nopts, sizeof(opts[0]), &opt_cmp);
    if (a_path_opt == NULL) {
        // Again, no path implies match to the root node.
        process_req_uri(req, nopts, opts, root);
    }
    // Now find the *first* occurrence of a path option.
    coap_msg_opt_t *first_path_opt;
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
    size_t npath_opts = 0;
    for (coap_msg_opt_t *opt = first_path_opt; opt < end && opt->num == COAP_OPT_PATH; ++opt) {
        ++npath_opts;
    }
    if (iter_req_uri(req, nopts, opts, npath_opts, first_path_opt, root)) {
        // Non-zero return from iter_req_uri means dispatch failed.
        // Discard req.
        coap_discard(req);
    }
}

/**
 * CoAP server entry point.  Parse incoming CoAP messages and, if apporpiate,
 * inject into the server for handling with the URI tree anchored at the passed
 * root node.
 *
 * @param req transport-agnostic CoAP message structure
 * @param root root node of tree to be used for handling incoming requests
 */
void coap_rx(coap_req_data_t * const req, const coap_node_t * const root)
{
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
        default:
            // We are acting strictly in the server role.
            // Ignore all other message types.
            coap_discard(req);
            return;
    }
    switch (req->msg->code.code_class) {
        case COAP_REQ:
            break;
        default:
            // All of our outgoing messages are non-confirmable.  Thus, we
            // expect no incoming messages other than requests.  If we do see
            // any other types, we can safely ignore these.
            coap_discard(req);
            return;
    }
    // Clear our ACK-transmission flag.
    ZCOAP_MEMSET(&req->state, 0, sizeof(req->state));
    // This is a valid request!  Inject into the server!
    inject_coap_req(req, root);
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

/**
 * Recursive CoAP URI tree sort iterator.  Also executes init on nodes where
 * init is specified.
 *
 * @param node root node from which to iterate
 */
static void iter_coap_sort(const coap_node_t * const node)
{
    coap_sort_children(node);
    for (const coap_node_t * const *c = node->children; c != NULL && *c != NULL; ++c) {
        if ((*c)->init) {
            (*(*c)->init)(*c);
        }
        iter_coap_sort(*c);
    }
    for (const coap_gen_t *g = node->gens; g != NULL && *g != NULL; ++g) {
        coap_meta_t iterator = 0;
        while (1) {
            coap_node_t dynamic_node = { .parent = node };
            if((**g)(&iterator, &dynamic_node)) {
                break;
            }
            if (dynamic_node.init) {
                (*dynamic_node.init)(&dynamic_node);
            }
            iter_coap_sort(&dynamic_node);
        }
    }
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
void coap_init(const coap_node_t * const root)
{
    iter_coap_sort(root);
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
coap_code_t __attribute__((nonnull (1, 4))) coap_count_query_opts(coap_req_data_t * const req, size_t nopts, const coap_msg_opt_t opts[], size_t * const nqueryopts)
{
    if ((opts == NULL && req == NULL) || nqueryopts == NULL) {
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
    coap_msg_opt_t lopts[nopts];
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
coap_code_t __attribute__((nonnull (1, 5))) coap_get_query_opts(coap_req_data_t * const req, size_t nopts, const coap_msg_opt_t opts[], const size_t nqueryopts, coap_msg_opt_t * const queryopts)
{
    if (nqueryopts == 0) {
        return 0;
    }
    if ((opts == NULL && req == NULL) || queryopts == NULL) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_code_t rc;
    if (opts == NULL && (rc = coap_count_opts(req, &nopts))) {
        return rc;
    }
    if (nqueryopts > nopts) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_msg_opt_t lopts[nopts];
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
extern uint8_t __attribute__((nonnull (4, 5))) coap_get_size1(coap_req_data_t * const req, size_t nopts, const coap_msg_opt_t opts[], bool * const found, uint32_t * const size1)
{
    if ((opts == NULL && req == NULL) || found == NULL || size1 == NULL) {
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
    coap_msg_opt_t *msg_size1;
    if (opts == NULL) {
        coap_msg_opt_t lopts[nopts];
        if ((rc = coap_get_opts(req, nopts, lopts))) {
            return rc;
        }
        const coap_msg_opt_t key = { .num = COAP_OPT_SIZE1 };
        msg_size1 = bsearch(&key, lopts, nopts, sizeof(lopts[0]), &opt_cmp);
        if (msg_size1 == NULL) {
            *found = false;
            return 0;
        }
    } else {
        const coap_msg_opt_t key = { .num = COAP_OPT_SIZE1 };
        msg_size1 = bsearch(&key, opts, nopts, sizeof(opts[0]), &opt_cmp);
        if (msg_size1 == NULL) {
            *found = false;
            return 0;
        }
    }
    *found = true;
    if (!msg_size1->len) {
        // Per RFC 7252, a zero-length option value field is simply empty.  And
        // this is legal for the size1 designator.  We'll interpret this as
        // unspecified / don't care.  To the caller, this will be equivalent to
        // the case where no size1 option was included at all.
        *found = false;
        return 0;
    } else if (msg_size1->len > sizeof(uint32_t)) {
        // size1 values larger than 4 bytes violate the RFC
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
    }
    memset(size1, 0, sizeof(*size1));
    ZCOAP_MEMCPY(size1, msg_size1->val, msg_size1->len);
    *size1 = ZCOAP_NTOHL(*size1);
    return 0;
}

/************** Begin string-to-numerical conversion functions. **************/

#if ULLONG_MAX == UINT64_MAX
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
 * @return 0 on success, an appropriate errno on error
 */
int coap_parse_ullong(const void * const ascii, const size_t len, unsigned long long * const out)
{
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return ENOMEM;
    }
    char buf[len + 1];
    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtoull(buf, &endptr, 0);
    if (!endptr || endptr == buf) {
        return EINVAL;
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
                return EINVAL;
            }
        } else if (   (tok = strstr(buf, "18446744073709551615"))
                   && !strpbrk(tok + strlen("18446744073709551615"), "0123456789")) {
            return 0;
        } else if (   (tok = strstr(buf, "01777777777777777777777"))
                   && !strpbrk(tok + strlen("01777777777777777777777"), "01234567")) {
            return 0;
        } else {
            return EINVAL;
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
 * @return 0 on success, an appropriate errno on error
 */
int coap_parse_llong(const void * const ascii, const size_t len, long long * const out)
{
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return ENOMEM;
    }
    char buf[len + 1];
    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtoll(buf, &endptr, 0);
    if (!endptr || endptr == buf) {
        return EINVAL;
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
                return EINVAL;
            }
        } else if (   (tok = strstr(buf, "9223372036854775807"))
                   && !strpbrk(tok + strlen("9223372036854775807"), "0123456789")) {
            return 0;
        } else if (   (tok = strstr(buf, "0777777777777777777777"))
                   && !strpbrk(tok + strlen("0777777777777777777777"), "01234567")) {
            return 0;
        } else {
            return EINVAL;
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
            return EINVAL;
        }
    }
    return 0;
}
#else
#error ullong and llong must be 64-bit!
#endif

#if ULONG_MAX == UINT64_MAX
int coap_parse_ulong(const void * const ascii, const size_t len, unsigned long * const out)
{
    return coap_parse_ullong(ascii, len, (unsigned long long *)out); // we checked width; this is OK
}

int coap_parse_long(const void * const ascii, const size_t len, long * const out)
{
    return coap_parse_llong(ascii, len, (long long *)out); // we checked width; this is OK
}
#elif ULONG_MAX == UINT32_MAX
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
 * @return 0 on success, an appropriate errno on error
 */
int coap_parse_ulong(const void * const ascii, const size_t len, unsigned long * const out)
{
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return ENOMEM;
    }
    char buf[len + 1];
    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtoul(buf, &endptr, 0);
    if (!endptr || endptr == buf) {
        return EINVAL;
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
                return EINVAL;
            }
        } else if (   (tok = strstr(buf, "4294967295"))
                   && !strpbrk(tok + strlen("4294967295"), "0123456789")) {
            return 0;
        } else if (   (tok = strstr(buf, "037777777777"))
                   && !strpbrk(tok + strlen("037777777777"), "01234567")) {
            return 0;
        } else {
            return EINVAL;
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
 * @return 0 on success, an appropriate errno on error
 */
int coap_parse_long(const void * const ascii, const size_t len, long * const out)
{
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return ENOMEM;
    }
    char buf[len + 1];
    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtol(buf, &endptr, 0);
    if (!endptr || endptr == buf) {
        return EINVAL;
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
                return EINVAL;
            }
        } else if (   (tok = strstr(buf, "2147483647"))
                   && !strpbrk(tok + strlen("2147483647"), "0123456789")) {
            return 0;
        } else if (   (tok = strstr(buf, "017777777777"))
                   && !strpbrk(tok + strlen("017777777777"), "01234567")) {
            return 0;
        } else {
            return EINVAL;
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
            return EINVAL;
        }
    }
    return 0;
}
#endif /* ULONG_MAX == UINT32_MAX */

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
 * @return 0 on success, an appropriate errno on error
 */
int coap_parse_uint(const void * const ascii, const size_t len, unsigned * const out)
{
    int rc;
    unsigned long ulong;
    if ((rc = coap_parse_ulong(ascii, len, &ulong))) {
        return rc;
    }
    if (ulong > UINT_MAX) {
        return EINVAL;
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
 * @return 0 on success, an appropriate errno on error
 */
int coap_parse_int(const void * const ascii, const size_t len, int * const out)
{
    int rc;
    long slong;
    if ((rc = coap_parse_long(ascii, len, &slong))) {
        return rc;
    }
    if (slong < INT_MIN || slong > INT_MAX) {
        return EINVAL;
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
 * @return 0 on success, an appropriate errno on error
 */
int coap_parse_float(const void * const ascii, const size_t len, float * const out)
{
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return ENOMEM;
    }
    char buf[len + 1];
    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtof(buf, &endptr);
    if (!endptr || endptr == buf) {
        return EINVAL;
    } else if (fabsf(*out) == HUGE_VALF) {
        return ERANGE; // presume overflow
    } else {
        int exponent;
        frexpf(*out, &exponent);
        if (exponent <= -126) { // 2^-126 is the smallest normal single-precision IEEE-754 float
            return ERANGE; // presume underflow
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
 * @return 0 on success, an appropriate errno on error
 */
int coap_parse_double(const void * const ascii, const size_t len, ZCOAP_DOUBLE * const out)
{
    if (len >= ZCOAP_MAX_BUF_SIZE) {
        return ENOMEM;
    }
    char buf[len + 1];
    ZCOAP_MEMCPY(buf, ascii, len);
    buf[len] = '\0'; // internally, we need strings null-terminated
    char *endptr = NULL;
    *out = strtod(buf, &endptr);
    if (!endptr || endptr == buf) {
        return EINVAL;
    } else if (fabs(*out) == HUGE_VAL) {
        return ERANGE; // presume overflow
    } else {
        int exponent;
        frexp(*out, &exponent);
        if (exponent <= -1022) { // 2^-1022 is the smallest normal double-precision IEEE-754 float
            return ERANGE; // presume underflow
        }
    }
    return 0;
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
coap_code_t __attribute__((nonnull(3, 4))) coap_parse_req_u64(const coap_ct_t ct, const size_t len, const void * const payload, uint64_t * const out)
{
    if (out == NULL) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    switch (ct) {
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_U16: {
            uint16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U32: {
            uint32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U64: {
            uint64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I16: {
            int16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            if (pval < 0) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I32: {
            int32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            if (pval < 0) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I64: {
            int64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            if (pval < 0) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_FLOAT: {
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
        case ZCOAP_FMT_DOUBLE: {
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
        #endif /* ZCOAP_EXTENSIONS */
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.
    int ec;
    unsigned long long ullong;
    if ((ec = coap_parse_ullong(payload, len, &ullong))) {
        switch (ec) {
            case ENOMEM:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
            default:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    }
    if (ullong > UINT64_MAX) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    *out = ullong;
    return 0;
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
coap_code_t __attribute__((nonnull(3, 4))) coap_parse_req_i64(const coap_ct_t ct, const size_t len, const void * const payload, int64_t * const out)
{
    if (out == NULL) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    switch (ct) {
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_U16: {
            uint16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U32: {
            uint32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U64: {
            uint64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            if (pval > INT64_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I16: {
            int16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I32: {
            int32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I64: {
            int64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_FLOAT: {
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
        case ZCOAP_FMT_DOUBLE: {
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
        #endif /* ZCOAP_EXTENSIONS */
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.
    int ec;
    long long llong;
    if ((ec = coap_parse_llong(payload, len, &llong))) {
        switch (ec) {
            case ENOMEM:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
            default:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    }
    if (llong < INT64_MIN || llong > INT64_MAX) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    *out = llong;
    return 0;
}

/**
 * Parse a uint32 from a CoAP payload.
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t __attribute__((nonnull(3, 4))) coap_parse_req_u32(const coap_ct_t ct, const size_t len, const void * const payload, uint32_t * const out)
{
    if (out == NULL) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    switch (ct) {
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_U16: {
            uint16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U32: {
            uint32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U64: {
            uint64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            if (pval > UINT32_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I16: {
            int16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            if (pval < 0) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I32: {
            int32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            if (pval < 0) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I64: {
            int64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            if (pval < 0 || pval > UINT32_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_FLOAT: {
            float pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHF(pval);
            if (pval < 0.0 || pval > UINT32_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            if (pval - *out != 0.0) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            return 0;
        }
        case ZCOAP_FMT_DOUBLE: {
            ZCOAP_DOUBLE pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHD(pval);
            if (pval < 0.0 || pval > UINT32_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            if (pval - *out != 0.0) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            return 0;
        }
        #endif /* ZCOAP_EXTENSIONS */
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.
    int ec;
    size_t size1;
    unsigned long ulong;
    if ((ec = coap_parse_ulong(payload, len, &ulong))) {
        switch (ec) {
            case ENOMEM:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
            default:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    }
    if (ulong > UINT32_MAX) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    *out = ulong;
    return 0;
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
coap_code_t __attribute__((nonnull(3, 4))) coap_parse_req_i32(const coap_ct_t ct, const size_t len, const void * const payload, int32_t * const out)
{
    if (out == NULL) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    switch (ct) {
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_U16: {
            uint16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U32: {
            uint32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            if (pval > INT32_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U64: {
            uint64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            if (pval > INT32_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I16: {
            int16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I32: {
            int32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I64: {
            int64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            if (pval < INT32_MIN || pval > INT32_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_FLOAT: {
            float pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHF(pval);
            if (pval < INT32_MIN || pval > INT32_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            if (pval - *out != 0.0) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            return 0;
        }
        case ZCOAP_FMT_DOUBLE: {
            ZCOAP_DOUBLE pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHD(pval);
            if (pval < INT32_MIN || pval > INT32_MAX) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            *out = pval;
            if (pval - *out != 0.0) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            return 0;
        }
        #endif /* ZCOAP_EXTENSIONS */
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.
    int ec;
    size_t size1;
    long slong;
    if ((ec = coap_parse_long(payload, len, &slong))) {
        switch (ec) {
            case ENOMEM:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
            default:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    }
    if (slong < INT32_MIN || slong > INT32_MAX) {
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
    }
    *out = slong;
    return 0;
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
coap_code_t __attribute__((nonnull(3, 4))) coap_parse_req_float(const coap_ct_t ct, const size_t len, const void * const payload, float * const out)
{
    if (out == NULL) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    switch (ct) {
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_U16: {
            uint16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U32: {
            uint32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U64: {
            uint64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I16: {
            int16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I32: {
            int32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I64: {
            int64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_FLOAT: {
            float pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            *out = ZCOAP_NTOHF(pval);
            return 0;
        }
        case ZCOAP_FMT_DOUBLE: {
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
        #endif /* ZCOAP_EXTENSIONS */
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.
    int ec;
    size_t size1;
    if ((ec = coap_parse_float(payload, len, out))) {
        switch (ec) {
            case ENOMEM:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
            default:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    }
    return 0;
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
coap_code_t __attribute__((nonnull(3, 4))) coap_parse_req_double(const coap_ct_t ct, const size_t len, const void * const payload, ZCOAP_DOUBLE * const out)
{
    if (out == NULL) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    switch (ct) {
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_U16: {
            uint16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U32: {
            uint32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_U64: {
            uint64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I16: {
            int16_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHS(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I32: {
            int32_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_I64: {
            int64_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHLL(pval);
            *out = pval;
            return 0;
        }
        case ZCOAP_FMT_FLOAT: {
            float pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            *out = ZCOAP_NTOHF(pval);
            return 0;
        }
        case ZCOAP_FMT_DOUBLE: {
            ZCOAP_DOUBLE pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            pval = ZCOAP_NTOHD(pval);
            *out = pval;
            return 0;
        }
        #endif /* ZCOAP_EXTENSIONS */
        case ZCOAP_FMT_NONE:
        case COAP_FMT_TEXT:
            break; // handled below
        default:
            return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT);
    }
    // Payload is plain text, or content format unspecified.  For maximum
    // compatibility, we presume plain text when content format is unspecified.
    // Use ASCII parser below.
    int ec;
    size_t size1;
    if ((ec = coap_parse_double(payload, len, out))) {
        switch (ec) {
            case ENOMEM:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE);
            default:
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
        }
    }
    return 0;
}

// Shallow 16-bit wrappers for the uint32 and int32 parsers

/**
 * Parse a uint16 from a CoAP payload.
 *
 * @param ct payload content type (ZCOAP_FMT_NONE if unspecified)
 * @param len payload length
 * @param payload payload data
 * @param out (out) caller-allocated write location for value parsed from request payload
 * @return 0 on success, non-zero CoAP status code (4.00-class or 5.00-class) on failure
 */
coap_code_t __attribute__((nonnull(3, 4))) coap_parse_req_u16(const coap_ct_t ct, const size_t len, const void * const payload, uint16_t * const out)
{
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
coap_code_t __attribute__((nonnull(3, 4))) coap_parse_req_i16(const coap_ct_t ct, const size_t len, const void *payload, int16_t * const out)
{
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
coap_code_t __attribute__((nonnull(3, 4))) coap_parse_req_bool(const coap_ct_t ct, const size_t len, const void * const payload, bool * const out)
{
    if (out == NULL) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    switch (ct) {
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_BOOL: {
            zcoap_bool_t pval;
            if (len != sizeof(pval)) {
                return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ);
            }
            ZCOAP_MEMCPY(&pval, payload, sizeof(pval));
            *out = TO_ZCOAP_BOOL(pval);
            return 0;
        }
        #endif /* ZCOAP_EXTENSIONS */
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
        *out = ZCOAP_TRUE;
        return 0;
    } else if (len >= strlen(ZCOAP_FALSE_STR) && !strncasecmp(payload, ZCOAP_FALSE_STR, len)) {
        *out = ZCOAP_FALSE;
        return 0;
    }
    // Truthiness strings were not found.  Fall back to attempting a numerical
    // text parse.
    int ival;
    int rc;
    if ((rc = coap_parse_req_int(ct, len, payload, &ival))) { // issues response and calls discard on our behalf if a parse error occurs
        return  rc;
    }
    *out = TO_ZCOAP_BOOL(ival);
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
        len = zvsnprintf(NULL, 0, fmt, ap);
        va_end(ap);
    }
    {
        char buf[len + 1];
        va_start(ap, fmt);
        len = zvsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_TEXT, len, buf);
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
    if ((coap_code = coap_get_content_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, val ? ZCOAP_TRUE_STR : ZCOAP_FALSE_STR);
            break;
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_AUTO:
        case ZCOAP_FMT_BOOL: {
            zcoap_bool_t _val = TO_ZCOAP_BOOL(val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ZCOAP_FMT_BOOL, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_U16:
        case ZCOAP_FMT_I16: {
            int16_t _val = TO_ZCOAP_BOOL(val);
            _val = ZCOAP_HTONS(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_U32:
        case ZCOAP_FMT_I32: {
            int32_t _val = TO_ZCOAP_BOOL(val);
            _val = ZCOAP_HTONL(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_U64:
        case ZCOAP_FMT_I64: {
            int64_t _val = TO_ZCOAP_BOOL(val);
            _val = ZCOAP_HTONLL(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_FLOAT: {
            float _val = TO_ZCOAP_BOOL(val);
            _val = ZCOAP_HTONF(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_DOUBLE: {
            ZCOAP_DOUBLE _val = TO_ZCOAP_BOOL(val);
            _val = ZCOAP_HTOND(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        #endif /* ZCOAP_EXTENSIONS */
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT));
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
    if ((coap_code = coap_get_content_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_U16, val);
            break;
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_AUTO:
        case ZCOAP_FMT_U16:
            val = ZCOAP_HTONS(val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ZCOAP_FMT_U16, sizeof(val), &val);
            break;
        case ZCOAP_FMT_U32:
        case ZCOAP_FMT_I32: {
            int32_t _val = val;
            _val = ZCOAP_HTONL(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_U64:
        case ZCOAP_FMT_I64: {
            int64_t _val = val;
            _val = ZCOAP_HTONLL(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_FLOAT: {
            float _val = val;
            _val = ZCOAP_HTONF(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_DOUBLE: {
            ZCOAP_DOUBLE _val = val;
            _val = ZCOAP_HTOND(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        #endif /* ZCOAP_EXTENSIONS */
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT));
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
    if ((coap_code = coap_get_content_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_U32, val);
            break;
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_AUTO:
        case ZCOAP_FMT_U32:
            val = ZCOAP_HTONL(val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ZCOAP_FMT_U32, sizeof(val), &val);
            break;
        case ZCOAP_FMT_U64:
        case ZCOAP_FMT_I64: {
            int64_t _val = val;
            _val = ZCOAP_HTONLL(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_DOUBLE: {
            ZCOAP_DOUBLE _val = val;
            _val = ZCOAP_HTOND(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        #endif /* ZCOAP_EXTENSIONS */
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT));
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
    if ((coap_code = coap_get_content_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_U64, val);
            break;
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_AUTO:
        case ZCOAP_FMT_U64:
            val = ZCOAP_HTONLL(val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ZCOAP_FMT_U64, sizeof(val), &val);
            break;
        #endif /* ZCOAP_EXTENSIONS */
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT));
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
    if ((coap_code = coap_get_content_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_I16, val);
            break;
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_AUTO:
        case ZCOAP_FMT_I16:
            val = ZCOAP_HTONS(val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ZCOAP_FMT_I16, sizeof(val), &val);
            break;
        case ZCOAP_FMT_I32: {
            int32_t _val = val;
            _val = ZCOAP_HTONL(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_I64: {
            int64_t _val = val;
            _val = ZCOAP_HTONLL(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_FLOAT: {
            float _val = val;
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_DOUBLE: {
            ZCOAP_DOUBLE _val = val;
            _val = ZCOAP_HTOND(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        #endif /* ZCOAP_EXTENSIONS */
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT));
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
    if ((coap_code = coap_get_content_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_I32, val);
            break;
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_AUTO:
        case ZCOAP_FMT_I32:
            val = ZCOAP_HTONL(val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ZCOAP_FMT_I32, sizeof(val), &val);
            break;
        case ZCOAP_FMT_I64: {
            int64_t _val = val;
            _val = ZCOAP_HTONLL(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        case ZCOAP_FMT_DOUBLE: {
            ZCOAP_DOUBLE _val = val;
            _val = ZCOAP_HTOND(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        #endif /* ZCOAP_EXTENSIONS */
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT));
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
    if ((coap_code = coap_get_content_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_I64, val);
            break;
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_AUTO:
        case ZCOAP_FMT_I64:
            val = ZCOAP_HTONLL(val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ZCOAP_FMT_I64, sizeof(val), &val);
            break;
        #endif /* ZCOAP_EXTENSIONS */
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT));
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
    if ((coap_code = coap_get_content_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_FLOAT, (double)val); // %f means double - period, and whatever that is; do *not* use ZCOAP_DOUBLE macro here
            break;
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_AUTO:
        case ZCOAP_FMT_FLOAT:
            val = ZCOAP_HTONF(val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ZCOAP_FMT_FLOAT, sizeof(val), &val);
            break;
        case ZCOAP_FMT_DOUBLE: {
            ZCOAP_DOUBLE _val = val;
            _val = ZCOAP_HTOND(_val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ct, sizeof(_val), &_val);
            break;
        }
        #endif /* ZCOAP_EXTENSIONS */
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT));
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
    if ((coap_code = coap_get_content_type(req, nopts, opts, &ct))) {
        coap_status_rsp(req, coap_code);
        return;
    }
    switch (ct) {
        case ZCOAP_FMT_NONE: // no content format option enclosed
        case COAP_FMT_TEXT: // default handling behavior is text return
            coap_printf(req, fmt ? fmt : RESPONSE_FMT_DOUBLE, (double)val); // %f means double - period, and whatever that is; do *not* use ZCOAP_DOUBLE macro here
            break;
        #ifdef ZCOAP_EXTENSIONS
        case ZCOAP_FMT_AUTO:
        case ZCOAP_FMT_DOUBLE:
            val = ZCOAP_HTOND(val);
            coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), ZCOAP_FMT_DOUBLE, sizeof(val), &val);
            break;
        #endif /* ZCOAP_EXTENSIONS */
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT));
            break;
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
void coap_get_bool( ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_BOOL,
    #endif
    ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        bool val = *(volatile bool *)node->data;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_U16,
    #endif
    ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        uint16_t val = *(volatile unsigned *)node->data;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_U32,
    #endif
    ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        uint32_t val = *(volatile uint32_t *)node->data;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_U64,
    #endif
    ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        uint64_t val = *(volatile uint64_t *)node->data;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_I16,
    #endif
    ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        int16_t val = *(volatile int16_t *)node->data;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_I32,
    #endif
    ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        uint32_t val = *(volatile uint32_t *)node->data;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_I64,
    #endif
    ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        int64_t val = *(volatile int64_t *)node->data;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_FLOAT,
    #endif
    ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        float val = *(volatile float *)node->data;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_DOUBLE,
    #endif
    ZCOAP_FMT_SENTINEL);
    if (!node->data) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        ZCOAP_DOUBLE val = *(volatile ZCOAP_DOUBLE *)node->data;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_BOOL,
    #endif
    ZCOAP_FMT_SENTINEL);
    bool val;
    coap_code_t code;
    if ((code = coap_parse_req_bool(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err = NULL;
    if (node->validate && (err = (*node->validate)(&val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        *(volatile bool *)(node->data) = val;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_U16,
    #endif
    ZCOAP_FMT_SENTINEL);
    uint16_t val;
    coap_code_t code;
    if ((code = coap_parse_req_u16(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err = NULL;
    if (node->validate && (err = (*node->validate)(&val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        *(volatile uint16_t *)(node->data) = val;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_U32,
    #endif
    ZCOAP_FMT_SENTINEL);
    uint32_t val;
    coap_code_t code;
    if ((code = coap_parse_req_u32(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err;
    if (node->validate && (err = (*node->validate)(&val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        *(volatile uint32_t *)(node->data) = val;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_U64,
    #endif
    ZCOAP_FMT_SENTINEL);
    uint64_t val;
    coap_code_t code;
    if ((code = coap_parse_req_u64(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err;
    if (node->validate && (err = (*node->validate)(&val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        *(volatile uint64_t *)(node->data) = val;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_I16,
    #endif
    ZCOAP_FMT_SENTINEL);
    int16_t val;
    coap_code_t code;
    if ((code = coap_parse_req_i16(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err;
    if (node->validate && (err = (*node->validate)(&val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        *(volatile int16_t *)(node->data) = val;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_I32,
    #endif
    ZCOAP_FMT_SENTINEL);
    int32_t val;
    coap_code_t code;
    if ((code = coap_parse_req_i32(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err = NULL;
    if (node->validate && (err = (*node->validate)(&val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        *(volatile int32_t *)(node->data) = val;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_I64,
    #endif
    ZCOAP_FMT_SENTINEL);
    int64_t val;
    coap_code_t code;
    if ((code = coap_parse_req_i64(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err = NULL;
    if (node->validate && (err = (*node->validate)(&val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        *(volatile int64_t *)(node->data) = val;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_FLOAT,
    #endif
    ZCOAP_FMT_SENTINEL);
    float val;
    coap_code_t code;
    if ((code = coap_parse_req_float(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err;
    if (node->validate && (err = (*node->validate)(&val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        *(volatile float *)(node->data) = val;
        ZCOAP_UNLOCK();
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
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT,
    #ifdef ZCOAP_EXTENSIONS
    ZCOAP_FMT_DOUBLE,
    #endif
    ZCOAP_FMT_SENTINEL);
    ZCOAP_DOUBLE val;
    coap_code_t code;
    if ((code = coap_parse_req_double(ct, len, payload, &val))) {
        coap_status_rsp(req, code);
        return;
    }
    const char *err;
    if (node->validate && (err = (*node->validate)(&val))) {
        coap_detail_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_REQ), err);
    } else if (node->data == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        ZCOAP_LOCK();
        *(volatile ZCOAP_DOUBLE *)(node->data) = val;
        ZCOAP_UNLOCK();
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
}

/**
 * Set content type bits in mask for the passed vector of content type designators.
 *
 * @param mask (out) mask to set with bits for passed designators
 * @param ... one or more content type designators
 */
void set_ct_mask(ct_mask_t *mask, ...)
{
    va_list ap;
    va_start(ap, mask);
    unsigned ct; // va_list element sizes will be platform-dependent; unsigned gets us the correct width
    while ((ct = va_arg(ap, unsigned)) != ZCOAP_FMT_SENTINEL) {
        switch (ct) {
            case COAP_FMT_TEXT:
                mask->ct_text = 1;
                break;
            case COAP_FMT_LINK:
                mask->ct_link = 1;
                break;
            case COAP_FMT_XML:
                mask->ct_xml = 1;
                break;
            case COAP_FMT_STREAM:
                mask->ct_ostream = 1;
                break;
            case COAP_FMT_EXI:
                mask->ct_exi = 1;
                break;
            case COAP_FMT_JSON:
                mask->ct_json = 1;
                break;
            #ifdef ZCOAP_EXTENSIONS
            case ZCOAP_FMT_BOOL:
                mask->ct_bool = 1;
                break;
            case ZCOAP_FMT_U16:
                mask->ct_u16 = 1;
                break;
            case ZCOAP_FMT_U32:
                mask->ct_u32 = 1;
                break;
            case ZCOAP_FMT_U64:
                mask->ct_u64 = 1;
                break;
            case ZCOAP_FMT_I16:
                mask->ct_i16 = 1;
                break;
            case ZCOAP_FMT_I32:
                mask->ct_i32 = 1;
                break;
            case ZCOAP_FMT_I64:
                mask->ct_i64 = 1;
                break;
            case ZCOAP_FMT_FLOAT:
                mask->ct_float = 1;
                break;
            case ZCOAP_FMT_DOUBLE:
                mask->ct_double = 1;
                break;
            #endif /* ZCOAP_EXTENSIONS */
        }
    }
    va_end(ap);
}

/**
 * Set mask with the single passed content type literal.  Content type need not
 * be known to us, but must be strictly less than 0xFF, which is a special code
 * for us.  Note also that we've committed for all time to NOT supporting
 * content type designators larger than a byte in size.
 *
 * @param mask content type mask to set with the literal value
 * @param ct content type literal
 */
void set_ct_mask_literal(ct_mask_t *mask, coap_ct_t ct)
{
    if (ct >= ZCOAP_FMT_SENTINEL) {
        return;
    }
    memset(mask, 0, sizeof(*mask));
    mask->ct_literal = ct;
    mask->literal_set = 1;
}
