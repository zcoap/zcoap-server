#include "../src/zcoap-server.h"

/**
 * fs_uri
 *
 * Example node for dynamic generation of CoAP tree nodes.  In this case, we
 * give a file listing from the server's file system.  Client's may then GET
 * these files.
 *
 * Of course, you might think twice about doing this in a real production
 * environment (security?)!  But this demonstrates some serious utility.
 */
extern const coap_node_t fs_uri;
