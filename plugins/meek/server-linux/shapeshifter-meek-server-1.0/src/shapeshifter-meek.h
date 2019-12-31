#ifndef OPENVPN_PLUGIN_shapeshifter_meek_H
#define OPENVPN_PLUGIN_shapeshifter_meek_H 1

#include "openvpn/openvpn-plugin.h"
#include "openvpn/openvpn-vsocket.h"

#define shapeshifter_meek_PLUGIN_NAME "shapeshifter-meek"

struct shapeshifter_meekserver_context
{
    struct openvpn_plugin_callbacks *global_vtab;

    char disableTLS;
    char *acmeEmail;
    char *acmeHostnamesCommas;
    char *stateDir;
};

extern struct openvpn_vsocket_vtab shapeshifter_meek_socket_vtab;
void shapeshifter_meek_initialize_socket_vtab(void);
void shapeshifter_meek_log(struct shapeshifter_meekserver_context *ctx, openvpn_plugin_log_flags_t flags, const char *fmt, ...);

#endif /* !OPENVPN_PLUGIN_shapeshifter_meek_H */
