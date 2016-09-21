/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "alloc-util.h"
#include "sd-bus.h"
#include "bus-util.h"
#include "bus-error.h"
#include "conf-parser.h"
#include "def.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "sleep-config.h"
#include "string-util.h"
#include "strv.h"

#define USE(x, y) do { (x) = (y); (y) = NULL; } while (0)

int parse_sleep_config(const char *verb, char ***_modes, char ***_states) {

        _cleanup_strv_free_ char
                **suspend_mode = NULL, **suspend_state = NULL,
                **hibernate_mode = NULL, **hibernate_state = NULL,
                **hybrid_mode = NULL, **hybrid_state = NULL;
        char **modes, **states;

        const ConfigTableItem items[] = {
                { "Sleep",   "SuspendMode",      config_parse_strv,  0, &suspend_mode  },
                { "Sleep",   "SuspendState",     config_parse_strv,  0, &suspend_state },
                { "Sleep",   "HibernateMode",    config_parse_strv,  0, &hibernate_mode  },
                { "Sleep",   "HibernateState",   config_parse_strv,  0, &hibernate_state },
                { "Sleep",   "HybridSleepMode",  config_parse_strv,  0, &hybrid_mode  },
                { "Sleep",   "HybridSleepState", config_parse_strv,  0, &hybrid_state },
                {}
        };

        config_parse_many_nulstr(PKGSYSCONFDIR "/sleep.conf",
                          CONF_PATHS_NULSTR("systemd/sleep.conf.d"),
                          "Sleep\0", config_item_table_lookup, items,
                          false, NULL);

        if (streq(verb, "suspend")) {
                /* empty by default */
                USE(modes, suspend_mode);

                if (suspend_state)
                        USE(states, suspend_state);
                else
                        states = strv_new("mem", "standby", "freeze", NULL);

        } else if (streq(verb, "hibernate")) {
                if (hibernate_mode)
                        USE(modes, hibernate_mode);
                else
                        modes = strv_new("platform", "shutdown", NULL);

                if (hibernate_state)
                        USE(states, hibernate_state);
                else
                        states = strv_new("disk", NULL);

        } else if (streq(verb, "hybrid-sleep")) {
                if (hybrid_mode)
                        USE(modes, hybrid_mode);
                else
                        modes = strv_new("suspend", "platform", "shutdown", NULL);

                if (hybrid_state)
                        USE(states, hybrid_state);
                else
                        states = strv_new("disk", NULL);

        } else
                assert_not_reached("what verb");

        if ((!modes && !streq(verb, "suspend")) || !states) {
                strv_free(modes);
                strv_free(states);
                return log_oom();
        }

        *_modes = modes;
        *_states = states;
        return 0;
}

static int parse_sleep_products_config(const char *verb, char ***_blacklist, char ***_whitelist) {

        _cleanup_strv_free_ char
                **suspend_blacklist = NULL, **suspend_whitelist = NULL,
                **hibernate_blacklist = NULL, **hibernate_whitelist = NULL,
                **hybrid_blacklist = NULL, **hybrid_whitelist = NULL;
        char **blacklist, **whitelist;

        const ConfigTableItem items[] = {
                { "CanSuspend",     "BlackListProducts", config_parse_strv,  0, &suspend_blacklist  },
                { "CanSuspend",     "WhiteListProducts", config_parse_strv,  0, &suspend_whitelist },
                { "CanHibernate",   "BlackListProducts", config_parse_strv,  0, &hibernate_blacklist  },
                { "CanHibernate",   "WhiteListProducts", config_parse_strv,  0, &hibernate_whitelist },
                { "CanHybridSleep", "BlackListProducts", config_parse_strv,  0, &hybrid_blacklist  },
                { "CanHybridSleep", "WhiteListProducts", config_parse_strv,  0, &hybrid_whitelist },
                {}
        };

        int r;
        _cleanup_fclose_ FILE *f;

        f = fopen(PKGSYSCONFDIR "/sleep-products.conf", "re");
        if (!f)
                log_full(errno == ENOENT ? LOG_DEBUG: LOG_WARNING,
                         "Failed to open configuration file " PKGSYSCONFDIR "/sleep-products.conf: %m");
        else {
                r = config_parse
                        (NULL, PKGSYSCONFDIR "/sleep-products.conf", f, "CanSuspend\0CanHibernate\0CanHybridSleep\0",
                                 config_item_table_lookup, (void*) items, false, false, false, NULL);
                if (r < 0)
                        log_warning("Failed to parse configuration file: %s", strerror(-r));
        }

        if (streq(verb, "suspend")) {
                USE(blacklist, suspend_blacklist);
                USE(whitelist, suspend_whitelist);
        } else if (streq(verb, "hibernate")) {
                USE(blacklist, hibernate_blacklist);
                USE(whitelist, hibernate_whitelist);
        } else if (streq(verb, "hybrid-sleep")) {
                USE(blacklist, hybrid_blacklist);
                USE(whitelist, hybrid_whitelist);
        } else
                assert_not_reached("what verb");

        *_blacklist = blacklist;
        *_whitelist = whitelist;
        return 0;
}

int can_sleep_state(char **types) {
        char **type;
        int r;
        _cleanup_free_ char *p = NULL;

        if (strv_isempty(types))
                return true;

        /* If /sys is read-only we cannot sleep */
        if (access("/sys/power/state", W_OK) < 0)
                return false;

        r = read_one_line_file("/sys/power/state", &p);
        if (r < 0)
                return false;

        STRV_FOREACH(type, types) {
                const char *word, *state;
                size_t l, k;

                k = strlen(*type);
                FOREACH_WORD_SEPARATOR(word, l, p, WHITESPACE, state)
                        if (l == k && memcmp(word, *type, l) == 0)
                                return true;
        }

        return false;
}

int can_sleep_disk(char **types) {
        char **type;
        int r;
        _cleanup_free_ char *p = NULL;

        if (strv_isempty(types))
                return true;

        /* If /sys is read-only we cannot sleep */
        if (access("/sys/power/disk", W_OK) < 0)
                return false;

        r = read_one_line_file("/sys/power/disk", &p);
        if (r < 0)
                return false;

        STRV_FOREACH(type, types) {
                const char *word, *state;
                size_t l, k;

                k = strlen(*type);
                FOREACH_WORD_SEPARATOR(word, l, p, WHITESPACE, state) {
                        if (l == k && memcmp(word, *type, l) == 0)
                                return true;

                        if (l == k + 2 &&
                            word[0] == '[' &&
                            memcmp(word + 1, *type, l - 2) == 0 &&
                            word[l-1] == ']')
                                return true;
                }
        }

        return false;
}

#define HIBERNATION_SWAP_THRESHOLD 0.98

static int hibernation_partition_size(size_t *size, size_t *used) {
        _cleanup_fclose_ FILE *f;
        unsigned i;

        assert(size);
        assert(used);

        f = fopen("/proc/swaps", "re");
        if (!f) {
                log_full(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
                         "Failed to retrieve open /proc/swaps: %m");
                assert(errno > 0);
                return -errno;
        }

        (void) fscanf(f, "%*s %*s %*s %*s %*s\n");

        for (i = 1;; i++) {
                _cleanup_free_ char *dev = NULL, *type = NULL;
                size_t size_field, used_field;
                int k;

                k = fscanf(f,
                           "%ms "   /* device/file */
                           "%ms "   /* type of swap */
                           "%zu "   /* swap size */
                           "%zu "   /* used */
                           "%*i\n", /* priority */
                           &dev, &type, &size_field, &used_field);
                if (k != 4) {
                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/swaps:%u", i);
                        continue;
                }

                if (streq(type, "partition") && endswith(dev, "\\040(deleted)")) {
                        log_warning("Ignoring deleted swapfile '%s'.", dev);
                        continue;
                }

                *size = size_field;
                *used = used_field;
                return 0;
        }

        log_debug("No swap partitions were found.");
        return -ENOSYS;
}

static bool enough_memory_for_hibernation(void) {
        _cleanup_free_ char *active = NULL;
        unsigned long long act = 0;
        size_t size = 0, used = 0;
        int r;

        if (getenv_bool("SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK") > 0)
                return true;

        /* TuxOnIce is an alternate implementation for hibernation.
         * It can be configured to compress the image to a file or an inactive
         * swap partition, so there's nothing more we can do here. */
        if (access("/sys/power/tuxonice", F_OK) == 0)
                return true;

        r = hibernation_partition_size(&size, &used);
        if (r < 0)
                return false;

        r = get_proc_field("/proc/meminfo", "Active(anon)", WHITESPACE, &active);
        if (r < 0) {
                log_error_errno(r, "Failed to retrieve Active(anon) from /proc/meminfo: %m");
                return false;
        }

        r = safe_atollu(active, &act);
        if (r < 0) {
                log_error_errno(r, "Failed to parse Active(anon) from /proc/meminfo: %s: %m",
                                active);
                return false;
        }

        r = act <= (size - used) * HIBERNATION_SWAP_THRESHOLD;
        log_debug("Hibernation is %spossible, Active(anon)=%llu kB, size=%zu kB, used=%zu kB, threshold=%.2g%%",
                  r ? "" : "im", act, size, used, 100*HIBERNATION_SWAP_THRESHOLD);

        return r;
}

static bool is_product_listed(char **products) {
        char **product;
        int r;
        _cleanup_free_ char *p = NULL;

        if (strv_isempty(products))
                return false;

        if (access("/sys/class/dmi/id/product_name", R_OK) < 0)
                return false;

        r = read_one_line_file("/sys/class/dmi/id/product_name", &p);
        if (r < 0)
                return false;

        STRV_FOREACH(product, products) {
                size_t l, k;

                l = strlen(p);
                k = strlen(*product);
                if (l == k && memcmp(p, *product, l) == 0)
                        return true;
        }

        return false;
}

static bool is_laptop_chassis(void) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        static int result = -1;
        const char *s;
        int r;

        /* This answer depends on the actual hardware
           so it won't change in subsequent calls. */
        if (result != -1)
                return result;

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                log_error("Failed to create bus connection: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        "Chassis",
                        &error, &reply, "s");
        if (r < 0) {
                log_error("Could not get property: %s", bus_error_message(&error, -r));
                goto finish;
        }

        r = sd_bus_message_read(reply, "s", &s);
        if (r < 0) {
                bus_log_parse_error(r);
                goto finish;
        }

        result = strcmp(s, "laptop") == 0;
finish:
        sd_bus_close(bus);

        /* This can be -1 if the chassis could not be checked */
        return result > 0;
}

int can_sleep(const char *verb) {
        _cleanup_strv_free_ char **modes = NULL, **states = NULL;
        _cleanup_strv_free_ char **blacklist = NULL, **whitelist = NULL;
        int r;
        bool whitelisted;

        assert(streq(verb, "suspend") ||
               streq(verb, "hibernate") ||
               streq(verb, "hybrid-sleep"));

        r = parse_sleep_config(verb, &modes, &states);
        if (r < 0)
                return false;

        if (!can_sleep_state(states) || !can_sleep_disk(modes))
                return false;

        /* We keep an optional white and black list (by product) to
         * control if we want to explicitly support sleep operations. */
        r = parse_sleep_products_config(verb, &blacklist, &whitelist);
        if (r < 0)
                return false;

        if (is_product_listed(blacklist))
                return false;

        whitelisted = is_product_listed(whitelist);

        /* We don't support sleep operations for non-laptop chassis
           unless the product has been explicitly white listed. */
        if (!is_laptop_chassis() && !whitelisted)
                return false;

        if (streq(verb, "suspend"))
                return true;

        /* Endless does not support hibernate or hybrid-sleep, see
           T13184. So allow it only if whitelisted. */
        return whitelisted && enough_memory_for_hibernation();
}
