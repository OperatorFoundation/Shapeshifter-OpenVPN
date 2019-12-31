#ifndef OPENVPN_PLUGIN_shapeshifter_meeklite_H
#define OPENVPN_PLUGIN_shapeshifter_meeklite_H 1

#include "openvpn/openvpn-plugin.h"
#include "openvpn/openvpn-vsocket.h"

#define shapeshifter_meeklite_PLUGIN_NAME "shapeshifter-meeklite"

struct MemoryStruct {
    char *memory;
    size_t size;
};

struct shapeshifter_meeklite_context //change struct
{
    struct openvpn_plugin_callbacks *global_vtab;

    char *URL;
    char *serverESNI;
    char *coverESNI;
    char *keyESNI;
    char *sessionIDHeader
    struct MemoryStruct chunk; //stores data received by an ESNI write for later use by the read function

};

extern struct openvpn_vsocket_vtab shapeshifter_meeklite_socket_vtab;
void shapeshifter_meeklite_initialize_socket_vtab(void);
void shapeshifter_meeklite_log(struct shapeshifter_meeklite_context *ctx, openvpn_plugin_log_flags_t flags, const char *fmt, ...);

#endif /* !OPENVPN_PLUGIN_shapeshifter_meeklite_H */
