#ifndef OPENVPN_PLUGIN_shapeshifter_meeklite_H
#define OPENVPN_PLUGIN_shapeshifter_meeklite_H 1

#include "openvpn/openvpn-plugin.h"
#include "openvpn/openvpn-vsocket.h"

#define shapeshifter_meeklite_PLUGIN_NAME "shapeshifter-meeklite"

struct shapeshifter_meeklite_context //change struct
{
    struct openvpn_plugin_callbacks *global_vtab;
    char *url;
    char *front;
};

extern struct openvpn_vsocket_vtab shapeshifter_meeklite_socket_vtab;
void shapeshifter_meeklite_initialize_socket_vtab(void);
void shapeshifter_meeklite_log(struct shapeshifter_meeklite_context *ctx, openvpn_plugin_log_flags_t flags, const char *fmt, ...);

#endif /* !OPENVPN_PLUGIN_shapeshifter_meeklite_H */
