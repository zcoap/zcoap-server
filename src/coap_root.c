
static const coap_node_t core_uri = { .name = "core", .GET = &dump_coap_tree };
static const coap_node_t *wellknown_children[] = { &core_uri, NULL };
static const coap_node_t wellknown_uri = { .name = ".well-known", .children = wellknown_children, .lockout_exempt = true };
static const coap_node_t *root_children[] = {
    #ifdef DEMO_MODE
    &demo_mode_uri,
    #endif
    #if HARDWARE_REVISION == 0x107
    // deprecated, moved to /syringe; only preserve deprecated interface in v107
    &deprecated_syringe_pump_uri,
    #endif
    #if HARDWARE_REVISION == 0x104 || HARDWARE_REVISION == 0x105
    #elif HARDWARE_REVISION == 0x106 || HARDWARE_REVISION == 0x107 || HARDWARE_REVISION == 0x200
    &pressure_uri, &syringe_pump_uri,
    #else
    #error unsupported hardware revision!
    #endif
    #if HARDWARE_REVISION == 0x104 || HARDWARE_REVISION == 0x105 || HARDWARE_REVISION == 0x106
    #elif HARDWARE_REVISION == 0x107 || HARDWARE_REVISION == 0x200
    &vacuum_uri,
    #else
    #error unsupported hardware revision!
    #endif
    #ifdef ENABLE_BRIDGE_BALANCE
    &zladder_uri,
    #endif
    &cart_uri, &gmr_uri, &heater_uri, &i2ca_uri, &i2cb_uri, &mux_uri, &nvram_uri, &signal_generator_uri, &stepper_uri, &sys_uri, &transducer_uri, &valve_uri, &wellknown_uri, NULL }; // register external modules here
static const coap_node_t root_uri = { .children = root_children, .GET = &coap_root_get };

