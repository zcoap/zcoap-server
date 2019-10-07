#include "zcoap-server.h"
#include <stdio.h>

static const coap_node_t core = { .name = "core", .GET = &dump_coap_tree };
static const coap_node_t *wellknown_children[] = { &core, NULL };
static const coap_node_t wellknown = { .name = ".well-known", .children = wellknown_children  };
static const coap_node_t *root_children[] = { &wellknown, NULL };
static const coap_node_t root = { .children = root_children };
