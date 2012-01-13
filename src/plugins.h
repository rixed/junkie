// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef PLUGINS_H_101007
#define PLUGINS_H_101007
#include <limits.h>
#include <ltdl.h>
#include "junkie/proto/proto.h"
#include "junkie/tools/queue.h"
#include "junkie/tools/mutex.h"

struct mutex plugins_mutex;  // protects the plugins list

LIST_HEAD(plugins, plugin) plugins;

struct plugin {
    LIST_ENTRY(plugin) entry;
    char libname[PATH_MAX];
    lt_dlhandle handle;
    proto_okfn_t *parse_callback;
};

void plugin_del_all(void);
int parser_callbacks(struct proto_info const *, size_t tot_cap_len, uint8_t const *tot_packet);

void plugins_init(void);
void plugins_fini(void);

#endif
