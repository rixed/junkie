// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <ltdl.h>
#include "junkie/tools/log.h"
#include "junkie/tools/mallocer.h"
#include "junkie/tools/ext.h"
#include "plugins.h"

struct mutex plugins_mutex;

struct plugins plugins = LIST_HEAD_INITIALIZER(plugins);

static bool really_unload_plugins = true;
EXT_PARAM_RW(really_unload_plugins, "really-unload-plugins", bool, "Should we go as far as calling dlclose when unloading a plugin ? If so, then some debug symbols may be missing.")

static int plugin_ctor(struct plugin *plugin, char const *libname)
{
    SLOG(LOG_DEBUG, "Loading plugin %s", libname);
    mutex_lock(&plugins_mutex);
    plugin->handle = lt_dlopen(libname);
    if (! plugin->handle && libname[0] != '/') {
        // Try to load the plugin from PKGLIBDIR
        char *fullpath = tempstr_printf("%s/%s", STRIZE(PKGLIBDIR), libname);
        plugin->handle = lt_dlopen(fullpath);
    }
    if (! plugin->handle) {
        mutex_unlock(&plugins_mutex);
        SLOG(LOG_CRIT, "Cannot load plugin %s: %s", libname, lt_dlerror());
        return -1;
    }
    snprintf(plugin->libname, sizeof(plugin->libname), "%s", libname);

    // Call the plugin initializer
    void (*on_load)(void) = lt_dlsym(plugin->handle, "on_load");
    if (on_load) on_load();

    LIST_INSERT_HEAD(&plugins, plugin, entry);
    mutex_unlock(&plugins_mutex);
    ext_rebind();
    return 0;
}

static struct plugin *plugin_new(char const *libname)
{
    MALLOCER(plugin);
    struct plugin *plugin = MALLOC(plugin, sizeof(*plugin));
    if (! plugin) return NULL;
    if (0 != plugin_ctor(plugin, libname)) {
        FREE(plugin);
        return NULL;
    }
    return plugin;
}

static void plugin_dtor(struct plugin *plugin)
{
    SLOG(LOG_DEBUG, "Unloading plugin %s", plugin->libname);
    LIST_REMOVE(plugin, entry);

    // Call the plugin finalizer
    void (*on_unload)(void) = lt_dlsym(plugin->handle, "on_unload");
    if (on_unload) on_unload();

    if (really_unload_plugins) {
        if (lt_dlclose(plugin->handle)) {
            SLOG(LOG_ERR, "Cannot unload plugin %s: %s", plugin->libname, lt_dlerror());
        }
    }
}

static void plugin_del(struct plugin *plugin)
{
    plugin_dtor(plugin);
    FREE(plugin);
}

void plugin_del_all(void)
{
    SLOG(LOG_DEBUG, "Unloading all plugins");

    mutex_lock(&plugins_mutex);
    struct plugin *plugin;
    while (NULL != (plugin = LIST_FIRST(&plugins))) {
        plugin_del(plugin);
    }
    mutex_unlock(&plugins_mutex);
}

static struct ext_function sg_load_plugin;
static SCM g_load_plugin(SCM filename)
{
    struct plugin *plugin = plugin_new(scm_to_tempstr(filename));
    return plugin ? SCM_BOOL_T:SCM_BOOL_F;
}

static struct plugin *plugin_lookup(char const *libname)
{
    struct plugin *plugin;
    LIST_LOOKUP_LOCKED(plugin, &plugins, entry, 0 == strcmp(libname, plugin->libname), &plugins_mutex);
    return plugin;
}

static struct ext_function sg_unload_plugin;
static SCM g_unload_plugin(SCM filename)
{
    struct plugin *plugin = plugin_lookup(scm_to_tempstr(filename));
    if (! plugin) return SCM_BOOL_F;

    plugin_del(plugin);
    return SCM_BOOL_T;
}

static struct ext_function sg_plugins;
static SCM g_plugins(void)
{
    SCM ret = SCM_EOL;
    struct plugin *plugin;
    mutex_lock(&plugins_mutex);
    LIST_FOREACH(plugin, &plugins, entry) {
        ret = scm_cons(scm_from_locale_string(plugin->libname), ret);
    }
    mutex_unlock(&plugins_mutex);
    return ret;
}

static unsigned inited;
void plugins_init(void)
{
    if (inited++) return;
    ext_init();
    mutex_init();
    mallocer_init();

    if (0 != lt_dlinit()) {
        DIE("Cannot init ltdl: %s", lt_dlerror());
    }
    ext_param_really_unload_plugins_init();
    mutex_ctor(&plugins_mutex, "plugins");

    ext_function_ctor(&sg_load_plugin,
        "load-plugin", 1, 0, 0, g_load_plugin,
        "(load-plugin \"path/to/plugin.so\"): load the given plugin into junkie\n"
        "(load-plugin \"plugin.so\"): load the plugin from " STRIZE(PKGLIBDIR) "\n"
        "Returns false if the load failed.");

    ext_function_ctor(&sg_unload_plugin,
        "unload-plugin", 1, 0, 0, g_unload_plugin,
        "(unload-plugin \"path/to/libplugin.so\"): unload the given plugin from junkie\n"
        "Returns false if the unload failed.");

    ext_function_ctor(&sg_plugins,
        "plugins", 0, 0, 0, g_plugins,
        "(plugins): returns a list of loaded plugins");
}

void plugins_fini(void)
{
    if (--inited) return;

    mutex_dtor(&plugins_mutex);
    ext_param_really_unload_plugins_fini();
    lt_dlexit();

    mallocer_fini();
    mutex_fini();
    ext_fini();
}
