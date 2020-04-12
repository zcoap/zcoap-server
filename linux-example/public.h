#include "zcoap-server.h"

/**
 * public_server_root
 *
 * Entry point into our statically defined tree of nodes to expose via our
 * exmaple public CoAP server.
 *
 * Some nodes allow GET and PUT.  Some just allow GET.  Some return static data.
 * Some return random data!
 */
extern const coap_node_t public_server_root;
