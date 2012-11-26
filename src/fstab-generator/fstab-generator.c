/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stdio.h>
#include <mntent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "util.h"
#include "unit-name.h"
#include "path-util.h"
#include "mount-setup.h"
#include "special.h"
#include "mkdir.h"
#include "virt.h"

static const char *arg_dest = "/tmp";
static bool arg_enabled = true;

static int device_name(const char *path, char **unit) {
        char *p;

        assert(path);

        if (!is_device_path(path))
                return 0;

        p = unit_name_from_path(path, ".device");
        if (!p)
                return log_oom();

        *unit = p;
        return 1;
}

static int mount_find_pri(struct mntent *me, int *ret) {
        char *end, *pri;
        unsigned long r;

        assert(me);
        assert(ret);

        pri = hasmntopt(me, "pri");
        if (!pri)
                return 0;

        pri += 4;

        errno = 0;
        r = strtoul(pri, &end, 10);
        if (errno != 0)
                return -errno;

        if (end == pri || (*end != ',' && *end != 0))
                return -EINVAL;

        *ret = (int) r;
        return 1;
}

static int add_swap(const char *what, struct mntent *me) {
        char *name = NULL, *unit = NULL, *lnk = NULL, *device = NULL;
        FILE *f = NULL;
        bool noauto, nofail;
        int r, pri = -1;

        assert(what);
        assert(me);

        r = mount_find_pri(me, &pri);
        if (r < 0) {
                log_error("Failed to parse priority");
                return pri;
        }

        noauto = !!hasmntopt(me, "noauto");
        nofail = !!hasmntopt(me, "nofail");

        name = unit_name_from_path(what, ".swap");
        if (!name) {
                r = log_oom();
                goto finish;
        }

        unit = strjoin(arg_dest, "/", name, NULL);
        if (!unit) {
                r = log_oom();
                goto finish;
        }

        f = fopen(unit, "wxe");
        if (!f) {
                r = -errno;
                log_error("Failed to create unit file %s: %m", unit);
                goto finish;
        }

        fputs("# Automatically generated by systemd-fstab-generator\n\n"
              "[Unit]\n"
              "SourcePath=/etc/fstab\n"
              "DefaultDependencies=no\n"
              "Conflicts=" SPECIAL_UMOUNT_TARGET "\n"
              "Before=" SPECIAL_UMOUNT_TARGET "\n", f);

        if (!noauto && !nofail)
                fputs("Before=" SPECIAL_SWAP_TARGET "\n", f);

        fprintf(f,
                "\n"
                "[Swap]\n"
                "What=%s\n",
                what);

        if (pri >= 0)
                fprintf(f,
                        "Priority=%i\n",
                        pri);

        fflush(f);
        if (ferror(f)) {
                log_error("Failed to write unit file %s: %m", unit);
                r = -errno;
                goto finish;
        }

        if (!noauto) {
                lnk = strjoin(arg_dest, "/" SPECIAL_SWAP_TARGET ".wants/", name, NULL);
                if (!lnk) {
                        r = log_oom();
                        goto finish;
                }

                mkdir_parents_label(lnk, 0755);
                if (symlink(unit, lnk) < 0) {
                        log_error("Failed to create symlink %s: %m", lnk);
                        r = -errno;
                        goto finish;
                }

                r = device_name(what, &device);
                if (r < 0)
                        goto finish;

                if (r > 0) {
                        free(lnk);
                        lnk = strjoin(arg_dest, "/", device, ".wants/", name, NULL);
                        if (!lnk) {
                                r = log_oom();
                                goto finish;
                        }

                        mkdir_parents_label(lnk, 0755);
                        if (symlink(unit, lnk) < 0) {
                                log_error("Failed to create symlink %s: %m", lnk);
                                r = -errno;
                                goto finish;
                        }
                }
        }

        r = 0;
finish:
        if (f)
                fclose(f);

        free(unit);
        free(lnk);
        free(name);
        free(device);

        return r;
}

static bool mount_is_network(struct mntent *me) {
        assert(me);

        return
                hasmntopt(me, "_netdev") ||
                fstype_is_network(me->mnt_type);
}

static int add_mount(const char *what, const char *where, struct mntent *me) {
        char *name = NULL, *unit = NULL, *lnk = NULL, *device = NULL, *automount_name = NULL, *automount_unit = NULL;
        FILE *f = NULL;
        bool noauto, nofail, automount, isbind, isnetwork;
        int r;
        const char *post, *pre;

        assert(what);
        assert(where);
        assert(me);

        if (streq(me->mnt_type, "autofs"))
                return 0;

        if (!is_path(where)) {
                log_warning("Mount point %s is not a valid path, ignoring.", where);
                return 0;
        }

        if (mount_point_is_api(where) ||
            mount_point_ignore(where))
                return 0;

        isnetwork = mount_is_network(me);
        isbind = !!hasmntopt(me, "bind");

        noauto = !!hasmntopt(me, "noauto");
        nofail = !!hasmntopt(me, "nofail");
        automount =
                hasmntopt(me, "comment=systemd.automount") ||
                hasmntopt(me, "x-systemd.automount");

        if (isnetwork) {
                post = SPECIAL_REMOTE_FS_TARGET;
                pre = SPECIAL_REMOTE_FS_PRE_TARGET;
        } else {
                post = SPECIAL_LOCAL_FS_TARGET;
                pre = SPECIAL_LOCAL_FS_PRE_TARGET;
        }

        name = unit_name_from_path(where, ".mount");
        if (!name) {
                r = log_oom();
                goto finish;
        }

        unit = strjoin(arg_dest, "/", name, NULL);
        if (!unit) {
                r = log_oom();
                goto finish;
        }

        f = fopen(unit, "wxe");
        if (!f) {
                r = -errno;
                log_error("Failed to create unit file %s: %m", unit);
                goto finish;
        }

        fputs("# Automatically generated by systemd-fstab-generator\n\n"
              "[Unit]\n"
              "SourcePath=/etc/fstab\n"
              "DefaultDependencies=no\n", f);

        if (!path_equal(where, "/"))
                fprintf(f,
                        "After=%s\n"
                        "Wants=%s\n"
                        "Conflicts=" SPECIAL_UMOUNT_TARGET "\n"
                        "Before=" SPECIAL_UMOUNT_TARGET "\n",
                        pre,
                        pre);


        if (!noauto && !nofail && !automount)
                fprintf(f,
                        "Before=%s\n",
                        post);

        fprintf(f,
                "\n"
                "[Mount]\n"
                "What=%s\n"
                "Where=%s\n"
                "Type=%s\n"
                "FsckPassNo=%i\n",
                what,
                where,
                me->mnt_type,
                me->mnt_passno);

        if (!isempty(me->mnt_opts) &&
            !streq(me->mnt_opts, "defaults"))
                fprintf(f,
                        "Options=%s\n",
                        me->mnt_opts);

        fflush(f);
        if (ferror(f)) {
                log_error("Failed to write unit file %s: %m", unit);
                r = -errno;
                goto finish;
        }

        if (!noauto) {
                lnk = strjoin(arg_dest, "/", post, nofail || automount ? ".wants/" : ".requires/", name, NULL);
                if (!lnk) {
                        r = log_oom();
                        goto finish;
                }

                mkdir_parents_label(lnk, 0755);
                if (symlink(unit, lnk) < 0) {
                        log_error("Failed to create symlink %s: %m", lnk);
                        r = -errno;
                        goto finish;
                }

                if (!isbind &&
                    !path_equal(where, "/")) {

                        r = device_name(what, &device);
                        if (r < 0)
                                goto finish;

                        if (r > 0) {
                                free(lnk);
                                lnk = strjoin(arg_dest, "/", device, ".wants/", name, NULL);
                                if (!lnk) {
                                        r = log_oom();
                                        goto finish;
                                }

                                mkdir_parents_label(lnk, 0755);
                                if (symlink(unit, lnk) < 0) {
                                        log_error("Failed to create symlink %s: %m", lnk);
                                        r = -errno;
                                        goto finish;
                                }
                        }
                }
        }

        if (automount && !path_equal(where, "/")) {
                automount_name = unit_name_from_path(where, ".automount");
                if (!name) {
                        r = log_oom();
                        goto finish;
                }

                automount_unit = strjoin(arg_dest, "/", automount_name, NULL);
                if (!automount_unit) {
                        r = log_oom();
                        goto finish;
                }

                fclose(f);
                f = fopen(automount_unit, "wxe");
                if (!f) {
                        r = -errno;
                        log_error("Failed to create unit file %s: %m", automount_unit);
                        goto finish;
                }

                fprintf(f,
                        "# Automatically generated by systemd-fstab-generator\n\n"
                        "[Unit]\n"
                        "SourcePath=/etc/fstab\n"
                        "DefaultDependencies=no\n"
                        "Conflicts=" SPECIAL_UMOUNT_TARGET "\n"
                        "Before=" SPECIAL_UMOUNT_TARGET " %s\n"
                        "\n"
                        "[Automount]\n"
                        "Where=%s\n",
                        post,
                        where);

                fflush(f);
                if (ferror(f)) {
                        log_error("Failed to write unit file %s: %m", automount_unit);
                        r = -errno;
                        goto finish;
                }

                free(lnk);
                lnk = strjoin(arg_dest, "/", post, nofail ? ".wants/" : ".requires/", automount_name, NULL);
                if (!lnk) {
                        r = log_oom();
                        goto finish;
                }

                mkdir_parents_label(lnk, 0755);
                if (symlink(automount_unit, lnk) < 0) {
                        log_error("Failed to create symlink %s: %m", lnk);
                        r = -errno;
                        goto finish;
                }
        }

        r = 0;
finish:
        if (f)
                fclose(f);

        free(unit);
        free(lnk);
        free(name);
        free(device);
        free(automount_name);
        free(automount_unit);

        return r;
}

static int parse_fstab(void) {
        FILE *f;
        int r = 0;
        struct mntent *me;

        errno = 0;
        f = setmntent("/etc/fstab", "r");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /etc/fstab: %m");
                return -errno;
        }

        while ((me = getmntent(f))) {
                char *where, *what;
                int k;

                what = fstab_node_to_udev_node(me->mnt_fsname);
                if (!what) {
                        r = log_oom();
                        goto finish;
                }

                where = strdup(me->mnt_dir);
                if (!where) {
                        r = log_oom();
                        free(what);
                        goto finish;
                }

                if (is_path(where))
                        path_kill_slashes(where);

                log_debug("Found entry what=%s where=%s type=%s", what, where, me->mnt_type);

                if (streq(me->mnt_type, "swap"))
                        k = add_swap(what, me);
                else
                        k = add_mount(what, where, me);

                free(what);
                free(where);

                if (k < 0)
                        r = k;
        }

finish:
        endmntent(f);
        return r;
}

static int parse_proc_cmdline(void) {
        char *line, *w, *state;
        int r;
        size_t l;

        if (detect_container(NULL) > 0)
                return 0;

        r = read_one_line_file("/proc/cmdline", &line);
        if (r < 0) {
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
                return 0;
        }

        FOREACH_WORD_QUOTED(w, l, line, state) {
                char *word;

                word = strndup(w, l);
                if (!word) {
                        r = log_oom();
                        goto finish;
                }

                if (startswith(word, "fstab=")) {
                        r = parse_boolean(word + 6);
                        if (r < 0)
                                log_warning("Failed to parse fstab switch %s. Ignoring.", word + 6);
                        else
                                arg_enabled = r;

                } else if (startswith(word, "rd.fstab=")) {

                        if (in_initrd()) {
                                r = parse_boolean(word + 6);
                                if (r < 0)
                                        log_warning("Failed to parse fstab switch %s. Ignoring.", word + 6);
                                else
                                        arg_enabled = r;
                        }

                } else if (startswith(word, "fstab.") ||
                           (in_initrd() && startswith(word, "rd.fstab."))) {

                        log_warning("Unknown kernel switch %s. Ignoring.", word);
                }

                free(word);
        }

        r = 0;

finish:
        free(line);
        return r;
}

int main(int argc, char *argv[]) {
        int r;

        if (argc > 1 && argc != 4) {
                log_error("This program takes three or no arguments.");
                return EXIT_FAILURE;
        }

        if (argc > 1)
                arg_dest = argv[1];

        log_set_target(LOG_TARGET_SAFE);
        log_parse_environment();
        log_open();

        umask(0022);

        if (parse_proc_cmdline() < 0)
                return EXIT_FAILURE;

        if (!arg_enabled)
                return EXIT_SUCCESS;

        r = parse_fstab();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
