#include "fs.h"
#include "private.h"

// The filesystem generator, coap_fs_gen, is very cool!  We can mount and
// reflect any node of the filesystem at any node in our CoAP URI tree.
// coap_fs_gen is recursive, so really does work just as a mount point.
//
// Make sure, however, anything 'mounted' has proper permissions set.  Anything
// accessible to the server and reflected by coap_fs_gen will be accessible to
// clients.
//
// To provide some interesting data for our *example* server, lets mount these:
//
// /tmp -> coap://tmp
// /sys/power -> coap://telemetry/power

static coap_lock_t tmp_lock = PTHREAD_MUTEX_INITIALIZER;
static coap_node_t tmp = { .name = "tmp", .gen = &coap_fs_gen, .GET = &coap_fs_get, .PUT = &coap_fs_put, .DEL = &coap_fs_delete, .metadata = "/tmp", .wildcard = &create_coap_fs_node, .lock = &tmp_lock };
static coap_node_t power = { .name = "power", .gen = &coap_fs_gen, .GET = &coap_fs_get, .metadata = "/sys/power", .wildcard = &create_coap_fs_node };
static coap_node_t *root_children[] = { &wellknown_uri, &tmp, &power, NULL };
const coap_node_t private_server_root = { .children = root_children };
