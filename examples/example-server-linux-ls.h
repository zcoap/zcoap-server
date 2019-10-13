#include "../src/zcoap-server.h"

/**
 * ls_uri
 *
 * Example node for dynamic generation of CoAP tree nodes.  In this case, we
 * give a file listing from the server's file system.  Client's may then GET
 * and PUT these files.
 *
 * Of course, you might think twice about doing this in a real production
 * environment!  But this shows some serious utility of the server.
 */
extern const coap_node_t ls_uri;
