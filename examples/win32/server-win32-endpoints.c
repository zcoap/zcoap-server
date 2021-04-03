//#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include "server-win32-endpoints.h"

static int server_digits = 8675309;
static char server_name[50] = { 'M', 'e', 'g', '3', '2' };
static int max_server_temperature = INT_MIN;

static void coap_put_server_name(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, ZCOAP_FMT_SENTINEL); // HEADER is always required and always first
    switch (ct) {
        case ZCOAP_FMT_NONE: // non-specified by client; presume default, text
        case COAP_FMT_TEXT:
            break;
        default:
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_CONTENT_FMT));
            return; // bail!  All non-text payloads are illegal!
    }
    if (len > sizeof(server_name) - 1 /* need space for null char */) {
        coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_REQ_TOO_LARGE));
        return; // name is too big!
    }
    memcpy(server_name, payload, len);
    server_name[len] = '\0'; // null-terminate; CoAP strings are *not* null terminated across the wire
    coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
}

static void coap_get_server_temperature(ZCOAP_METHOD_SIGNATURE)
{
	ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, COAP_FMT_CBOR, ZCOAP_FMT_SENTINEL);

    int temperature = rand() % 100;

    max_server_temperature = temperature > max_server_temperature ? temperature : max_server_temperature; // store max

    coap_return_int(req, nopts, opts, NULL, temperature);
}

// Example tree
// /telemetry/temperature/
// /telemetry/temperature/max
// /telemetry/digits
// /telemetry/name
static coap_node_t name = { .name = "name", .GET = &coap_get_string, .PUT = &coap_put_server_name, .data = &server_name };
static coap_node_t digits = { .name = "digits", .GET = &coap_get_int, .PUT = &coap_put_int, .data = &server_digits };
static coap_node_t max_temperature = { .name = "max", .GET = &coap_get_int, .data = &max_server_temperature };
static coap_node_t *temperature_children[] = { &max_temperature, NULL };
static coap_node_t temperature = { .name = "temperature", .GET = &coap_get_server_temperature, .children = temperature_children };
static coap_node_t *telemetry_children[] = { &temperature, &digits, &name, NULL };
coap_node_t telemetry_uri = { .name = "telemetry", .children = telemetry_children };
