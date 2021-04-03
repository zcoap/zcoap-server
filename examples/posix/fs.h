#include "zcoap-server.h"

extern coap_code_t create_coap_fs_node(const coap_node_t * const parent, const char *name, coap_recurse_t recursor, const void *recursor_data);
extern coap_code_t coap_fs_gen(const coap_node_t * const parent, coap_recurse_t recursor, const void *recursor_data);

extern void coap_fs_get(ZCOAP_METHOD_SIGNATURE);
extern void coap_fs_put(ZCOAP_METHOD_SIGNATURE);
extern void coap_fs_post(ZCOAP_METHOD_SIGNATURE);
extern void coap_fs_delete(ZCOAP_METHOD_SIGNATURE);
