#ifndef OPENVPN_PLUGIN_shapeshifter_shadow_H
#define OPENVPN_PLUGIN_shapeshifter_shadow_H 1

#include "openvpn/openvpn-plugin.h"
#include "openvpn/openvpn-vsocket.h"

#define shapeshifter_shadow_PLUGIN_NAME "shapeshifter-shadow"

struct shapeshifter_shadow_context
{
    struct openvpn_plugin_callbacks *global_vtab;
    char *password;
    char *cipherName;
};

extern struct openvpn_vsocket_vtab shapeshifter_shadow_socket_vtab;
void shapeshifter_shadow_initialize_socket_vtab(void);
void shapeshifter_shadow_log(struct shapeshifter_shadow_context *ctx, openvpn_plugin_log_flags_t flags, const char *fmt, ...);

#endif /* !OPENVPN_PLUGIN_shapeshifter_shadow_H */
