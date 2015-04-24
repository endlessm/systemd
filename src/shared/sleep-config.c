/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2018 Dell Inc.
***/

#include <errno.h>
#include <linux/fs.h>
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

int parse_sleep_config(const char *verb, char ***_modes, char ***_states, usec_t *_delay) {

        _cleanup_strv_free_ char
                **suspend_mode = NULL, **suspend_state = NULL,
                **hibernate_mode = NULL, **hibernate_state = NULL,
                **hybrid_mode = NULL, **hybrid_state = NULL;
        _cleanup_strv_free_ char **modes, **states; /* always initialized below */
        usec_t delay = 180 * USEC_PER_MINUTE;

        const ConfigTableItem items[] = {
                { "Sleep",   "SuspendMode",      config_parse_strv,  0, &suspend_mode  },
                { "Sleep",   "SuspendState",     config_parse_strv,  0, &suspend_state },
                { "Sleep",   "HibernateMode",    config_parse_strv,  0, &hibernate_mode  },
                { "Sleep",   "HibernateState",   config_parse_strv,  0, &hibernate_state },
                { "Sleep",   "HybridSleepMode",  config_parse_strv,  0, &hybrid_mode  },
                { "Sleep",   "HybridSleepState", config_parse_strv,  0, &hybrid_state },
                { "Sleep",   "HibernateDelaySec", config_parse_sec,  0, &delay},
                {}
        };

        (void) config_parse_many_nulstr(PKGSYSCONFDIR "/sleep.conf",
                                        CONF_PATHS_NULSTR("systemd/sleep.conf.d"),
                                        "Sleep\0", config_item_table_lookup, items,
                                        CONFIG_PARSE_WARN, NULL);

        if (streq(verb, "suspend")) {
                /* empty by default */
                modes = TAKE_PTR(suspend_mode);

                if (suspend_state)
                        states = TAKE_PTR(suspend_state);
                else
                        states = strv_new("mem", "standby", "freeze", NULL);

        } else if (streq(verb, "hibernate")) {
                if (hibernate_mode)
                        modes = TAKE_PTR(hibernate_mode);
                else
                        modes = strv_new("platform", "shutdown", NULL);

                if (hibernate_state)
                        states = TAKE_PTR(hibernate_state);
                else
                        states = strv_new("disk", NULL);

        } else if (streq(verb, "hybrid-sleep")) {
                if (hybrid_mode)
                        modes = TAKE_PTR(hybrid_mode);
                else
                        modes = strv_new("suspend", "platform", "shutdown", NULL);

                if (hybrid_state)
                        states = TAKE_PTR(hybrid_state);
                else
                        states = strv_new("disk", NULL);

        } else if (streq(verb, "suspend-then-hibernate"))
                modes = states = NULL;
        else
                assert_not_reached("what verb");

        if ((!modes && STR_IN_SET(verb, "hibernate", "hybrid-sleep")) ||
            (!states && !streq(verb, "suspend-then-hibernate")))
                return log_oom();

        if (_modes)
                *_modes = TAKE_PTR(modes);
        if (_states)
                *_states = TAKE_PTR(states);
        if (_delay)
                *_delay = delay;

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
                                 config_item_table_lookup, (void*) items, 0, NULL);
                if (r < 0)
                        log_warning("Failed to parse configuration file: %s", strerror(-r));
        }

        if (streq(verb, "suspend")) {
                blacklist = TAKE_PTR(suspend_blacklist);
                whitelist = TAKE_PTR(suspend_whitelist);
        } else if (streq(verb, "hibernate")) {
                blacklist = TAKE_PTR(hibernate_blacklist);
                whitelist = TAKE_PTR(hibernate_whitelist);
        } else if (streq(verb, "hybrid-sleep")) {
                blacklist = TAKE_PTR(hybrid_blacklist);
                whitelist = TAKE_PTR(hybrid_whitelist);
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

int find_hibernate_location(char **device, char **type, size_t *size, size_t *used) {
        _cleanup_fclose_ FILE *f;
        unsigned i;

        f = fopen("/proc/swaps", "re");
        if (!f) {
                log_full(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
                         "Failed to retrieve open /proc/swaps: %m");
                assert(errno > 0);
                return -errno;
        }

        (void) fscanf(f, "%*s %*s %*s %*s %*s\n");

        for (i = 1;; i++) {
                _cleanup_free_ char *dev_field = NULL, *type_field = NULL;
                size_t size_field, used_field;
                int k;

                k = fscanf(f,
                           "%ms "   /* device/file */
                           "%ms "   /* type of swap */
                           "%zu "   /* swap size */
                           "%zu "   /* used */
                           "%*i\n", /* priority */
                           &dev_field, &type_field, &size_field, &used_field);
                if (k != 4) {
                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/swaps:%u", i);
                        continue;
                }

                if (streq(type_field, "partition") && endswith(dev_field, "\\040(deleted)")) {
                        log_warning("Ignoring deleted swapfile '%s'.", dev_field);
                        continue;
                }
                if (device)
                        *device = TAKE_PTR(dev_field);
                if (type)
                        *type = TAKE_PTR(type_field);
                if (size)
                        *size = size_field;
                if (used)
                        *used = used_field;
                return 0;
        }

        log_debug("No swap partitions were found.");
        return -ENOSYS;
}

static bool enough_swap_for_hibernation(void) {
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

        r = find_hibernate_location(NULL, NULL, &size, &used);
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

int read_fiemap(int fd, struct fiemap **ret) {
        _cleanup_free_ struct fiemap *fiemap = NULL, *result_fiemap = NULL;
        struct stat statinfo;
        uint32_t result_extents = 0;
        uint64_t fiemap_start = 0, fiemap_length;
        const size_t n_extra = DIV_ROUND_UP(sizeof(struct fiemap), sizeof(struct fiemap_extent));
        size_t fiemap_allocated = n_extra, result_fiemap_allocated = n_extra;

        if (fstat(fd, &statinfo) < 0)
                return log_debug_errno(errno, "Cannot determine file size: %m");
        if (!S_ISREG(statinfo.st_mode))
                return -ENOTTY;
        fiemap_length = statinfo.st_size;

        /* Zero this out in case we run on a file with no extents */
        fiemap = calloc(n_extra, sizeof(struct fiemap_extent));
        if (!fiemap)
                return -ENOMEM;

        result_fiemap = malloc_multiply(n_extra, sizeof(struct fiemap_extent));
        if (!result_fiemap)
                return -ENOMEM;

        /*  XFS filesystem has incorrect implementation of fiemap ioctl and
         *  returns extents for only one block-group at a time, so we need
         *  to handle it manually, starting the next fiemap call from the end
         *  of the last extent
         */
        while (fiemap_start < fiemap_length) {
                *fiemap = (struct fiemap) {
                        .fm_start = fiemap_start,
                        .fm_length = fiemap_length,
                        .fm_flags = FIEMAP_FLAG_SYNC,
                };

                /* Find out how many extents there are */
                if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0)
                        return log_debug_errno(errno, "Failed to read extents: %m");

                /* Nothing to process */
                if (fiemap->fm_mapped_extents == 0)
                        break;

                /* Resize fiemap to allow us to read in the extents, result fiemap has to hold all
                 * the extents for the whole file. Add space for the initial struct fiemap. */
                if (!greedy_realloc0((void**) &fiemap, &fiemap_allocated,
                                     n_extra + fiemap->fm_mapped_extents, sizeof(struct fiemap_extent)))
                        return -ENOMEM;

                fiemap->fm_extent_count = fiemap->fm_mapped_extents;
                fiemap->fm_mapped_extents = 0;

                if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0)
                        return log_debug_errno(errno, "Failed to read extents: %m");

                /* Resize result_fiemap to allow us to copy in the extents */
                if (!greedy_realloc((void**) &result_fiemap, &result_fiemap_allocated,
                                    n_extra + result_extents + fiemap->fm_mapped_extents, sizeof(struct fiemap_extent)))
                        return -ENOMEM;

                memcpy(result_fiemap->fm_extents + result_extents,
                       fiemap->fm_extents,
                       sizeof(struct fiemap_extent) * fiemap->fm_mapped_extents);

                result_extents += fiemap->fm_mapped_extents;

                /* Highly unlikely that it is zero */
                if (_likely_(fiemap->fm_mapped_extents > 0)) {
                        uint32_t i = fiemap->fm_mapped_extents - 1;

                        fiemap_start = fiemap->fm_extents[i].fe_logical +
                                       fiemap->fm_extents[i].fe_length;

                        if (fiemap->fm_extents[i].fe_flags & FIEMAP_EXTENT_LAST)
                                break;
                }
        }

        memcpy(result_fiemap, fiemap, sizeof(struct fiemap));
        result_fiemap->fm_mapped_extents = result_extents;
        *ret = TAKE_PTR(result_fiemap);
        return 0;
}

static bool can_s2h(void) {
        const char *p;
        int r;

        r = access("/sys/class/rtc/rtc0/wakealarm", W_OK);
        if (r < 0) {
                log_full(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
                         "/sys/class/rct/rct0/wakealarm is not writable %m");
                return false;
        }

        FOREACH_STRING(p, "suspend", "hibernate") {
                r = can_sleep(p);
                if (IN_SET(r, 0, -ENOSPC)) {
                        log_debug("Unable to %s system.", p);
                        return false;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to check if %s is possible: %m", p);
        }

        return true;
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

        assert(STR_IN_SET(verb, "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate"));

        if (streq(verb, "suspend-then-hibernate"))
                return can_s2h();

        r = parse_sleep_config(verb, &modes, &states, NULL);
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

        /* We don't support sleep operations for non-laptop chassis
           unless the product has been explicitly white listed. */
        if (!is_laptop_chassis() && !is_product_listed(whitelist))
                return false;

        if (streq(verb, "suspend"))
                return true;

        if (!enough_swap_for_hibernation())
                return -ENOSPC;

        return true;
}
