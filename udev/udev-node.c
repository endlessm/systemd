/*
 * Copyright (C) 2003-2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"

#define TMP_FILE_EXT		".udev-tmp"

int udev_node_mknod(struct udev_device *dev, const char *file, dev_t devnum, mode_t mode, uid_t uid, gid_t gid)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct stat stats;
	int preserve = 0;
	int err = 0;

	if (major(devnum) == 0)
		devnum = udev_device_get_devnum(dev);

	if (strcmp(udev_device_get_subsystem(dev), "block") == 0)
		mode |= S_IFBLK;
	else
		mode |= S_IFCHR;

	if (file == NULL)
		file = udev_device_get_devnode(dev);

	if (lstat(file, &stats) == 0) {
		if (((stats.st_mode & S_IFMT) == (mode & S_IFMT)) && (stats.st_rdev == devnum)) {
			info(udev, "preserve file '%s', because it has correct dev_t\n", file);
			preserve = 1;
			udev_selinux_lsetfilecon(udev, file, mode);
			/* update time stamp when we re-use the node, like on media change events */
			utimes(file, NULL);
		} else {
			char file_tmp[UTIL_PATH_SIZE + sizeof(TMP_FILE_EXT)];

			info(udev, "atomically replace existing file '%s'\n", file);
			util_strscpyl(file_tmp, sizeof(file_tmp), file, TMP_FILE_EXT, NULL);
			unlink(file_tmp);
			udev_selinux_setfscreatecon(udev, file_tmp, mode);
			err = mknod(file_tmp, mode, devnum);
			udev_selinux_resetfscreatecon(udev);
			if (err != 0) {
				err(udev, "mknod(%s, %#o, %u, %u) failed: %m\n",
				    file_tmp, mode, major(devnum), minor(devnum));
				goto exit;
			}
			err = rename(file_tmp, file);
			if (err != 0) {
				err(udev, "rename(%s, %s) failed: %m\n", file_tmp, file);
				unlink(file_tmp);
			}
		}
	} else {
		info(udev, "mknod(%s, %#o, (%u,%u))\n", file, mode, major(devnum), minor(devnum));
		do {
			err = util_create_path(udev, file);
			if (err != 0 && err != -ENOENT)
				break;
			udev_selinux_setfscreatecon(udev, file, mode);
			err = mknod(file, mode, devnum);
			if (err != 0)
				err = -errno;
			udev_selinux_resetfscreatecon(udev);
		} while (err == -ENOENT);
		if (err != 0) {
			err(udev, "mknod(%s, %#o, (%u,%u) failed: %m\n", file, mode, major(devnum), minor(devnum));
			goto exit;
		}
	}

	if (!preserve || stats.st_mode != mode) {
		info(udev, "chmod(%s, %#o)\n", file, mode);
		err = chmod(file, mode);
		if (err != 0) {
			err(udev, "chmod(%s, %#o) failed: %m\n", file, mode);
			goto exit;
		}
	}

	if (!preserve || stats.st_uid != uid || stats.st_gid != gid) {
		info(udev, "chown(%s, %u, %u)\n", file, uid, gid);
		err = chown(file, uid, gid);
		if (err != 0) {
			err(udev, "chown(%s, %u, %u) failed: %m\n", file, uid, gid);
			goto exit;
		}
	}
exit:
	return err;
}

static int node_symlink(struct udev *udev, const char *node, const char *slink)
{
	struct stat stats;
	char target[UTIL_PATH_SIZE];
	char *s;
	size_t l;
	char slink_tmp[UTIL_PATH_SIZE + sizeof(TMP_FILE_EXT)];
	int i = 0;
	int tail = 0;
	int err = 0;

	/* use relative link */
	target[0] = '\0';
	while (node[i] && (node[i] == slink[i])) {
		if (node[i] == '/')
			tail = i+1;
		i++;
	}
	s = target;
	l = sizeof(target);
	while (slink[i] != '\0') {
		if (slink[i] == '/')
			l = util_strpcpy(&s, l, "../");
		i++;
	}
	l = util_strscpy(s, l, &node[tail]);
	if (l == 0) {
		err = -EINVAL;
		goto exit;
	}

	/* preserve link with correct target, do not replace node of other device */
	if (lstat(slink, &stats) == 0) {
		if (S_ISBLK(stats.st_mode) || S_ISCHR(stats.st_mode)) {
			struct stat stats2;

			info(udev, "found existing node instead of symlink '%s'\n", slink);
			if (lstat(node, &stats2) == 0) {
				if ((stats.st_mode & S_IFMT) == (stats2.st_mode & S_IFMT) &&
				    stats.st_rdev == stats2.st_rdev && stats.st_ino != stats2.st_ino) {
					info(udev, "replace device node '%s' with symlink to our node '%s'\n",
					     slink, node);
				} else {
					err(udev, "device node '%s' already exists, "
					    "link to '%s' will not overwrite it\n",
					    slink, node);
					goto exit;
				}
			}
		} else if (S_ISLNK(stats.st_mode)) {
			char buf[UTIL_PATH_SIZE];
			int len;

			dbg(udev, "found existing symlink '%s'\n", slink);
			len = readlink(slink, buf, sizeof(buf));
			if (len > 0) {
				buf[len] = '\0';
				if (strcmp(target, buf) == 0) {
					info(udev, "preserve already existing symlink '%s' to '%s'\n",
					     slink, target);
					udev_selinux_lsetfilecon(udev, slink, S_IFLNK);
					lutimes(slink, NULL);
					goto exit;
				}
			}
		}
	} else {
		info(udev, "creating symlink '%s' to '%s'\n", slink, target);
		do {
			err = util_create_path(udev, slink);
			if (err != 0 && err != -ENOENT)
				break;
			udev_selinux_setfscreatecon(udev, slink, S_IFLNK);
			err = symlink(target, slink);
			if (err != 0)
				err = -errno;
			udev_selinux_resetfscreatecon(udev);
		} while (err == -ENOENT);
		if (err == 0)
			goto exit;
	}

	info(udev, "atomically replace '%s'\n", slink);
	util_strscpyl(slink_tmp, sizeof(slink_tmp), slink, TMP_FILE_EXT, NULL);
	unlink(slink_tmp);
	do {
		err = util_create_path(udev, slink_tmp);
		if (err != 0 && err != -ENOENT)
			break;
		udev_selinux_setfscreatecon(udev, slink_tmp, S_IFLNK);
		err = symlink(target, slink_tmp);
		if (err != 0)
			err = -errno;
		udev_selinux_resetfscreatecon(udev);
	} while (err == -ENOENT);
	if (err != 0) {
		err(udev, "symlink(%s, %s) failed: %m\n", target, slink_tmp);
		goto exit;
	}
	err = rename(slink_tmp, slink);
	if (err != 0) {
		err(udev, "rename(%s, %s) failed: %m\n", slink_tmp, slink);
		unlink(slink_tmp);
	}
exit:
	return err;
}

/* find device node of device with highest priority */
static const char *link_find_prioritized(struct udev_device *dev, bool add, const char *stackdir, char *buf, size_t bufsize)
{
	struct udev *udev = udev_device_get_udev(dev);
	DIR *dir;
	int priority = 0;
	const char *target = NULL;

	if (add) {
		priority = udev_device_get_devlink_priority(dev);
		util_strscpy(buf, bufsize, udev_device_get_devnode(dev));
		target = buf;
	}

	dir = opendir(stackdir);
	if (dir == NULL)
		return target;
	for (;;) {
		struct udev_device *dev_db;
		struct dirent *dent;
		char devpath[UTIL_PATH_SIZE];
		char syspath[UTIL_PATH_SIZE];
		ssize_t len;

		dent = readdir(dir);
		if (dent == NULL || dent->d_name[0] == '\0')
			break;
		if (dent->d_name[0] == '.')
			continue;
		dbg(udev, "found '%s/%s'\n", stackdir, dent->d_name);
		len = readlinkat(dirfd(dir), dent->d_name, devpath, sizeof(devpath));
		if (len <= 0 || len == (ssize_t)sizeof(devpath))
			continue;
		devpath[len] = '\0';
		util_strscpyl(syspath, sizeof(syspath), udev_get_sys_path(udev), devpath, NULL);
		info(udev, "found '%s' claiming '%s'\n", syspath, stackdir);

		/* did we find ourself? */
		if (strcmp(udev_device_get_syspath(dev), syspath) == 0)
			continue;

		dev_db = udev_device_new_from_syspath(udev, syspath);
		if (dev_db != NULL) {
			const char *devnode;

			devnode = udev_device_get_devnode(dev_db);
			if (devnode != NULL) {
				dbg(udev, "compare priority of '%s'(%i) > '%s'(%i)\n", target, priority,
				    udev_device_get_devnode(dev_db), udev_device_get_devlink_priority(dev_db));
				if (target == NULL || udev_device_get_devlink_priority(dev_db) > priority) {
					info(udev, "'%s' claims priority %i for '%s'\n",
					     syspath, udev_device_get_devlink_priority(dev_db), stackdir);
					priority = udev_device_get_devlink_priority(dev_db);
					util_strscpy(buf, bufsize, devnode);
					target = buf;
				}
			}
			udev_device_unref(dev_db);
		}
	}
	closedir(dir);
	return target;
}

/* manage "stack of names" with possibly specified device priorities */
static void link_update(struct udev_device *dev, const char *slink, bool add)
{
	struct udev *udev = udev_device_get_udev(dev);
	char name_enc[UTIL_PATH_SIZE];
	char filename[UTIL_PATH_SIZE * 2];
	char dirname[UTIL_PATH_SIZE];
	const char *target;
	char buf[UTIL_PATH_SIZE];

	dbg(udev, "update symlink '%s' of '%s'\n", slink, udev_device_get_syspath(dev));

	util_path_encode(&slink[strlen(udev_get_dev_path(udev))+1], name_enc, sizeof(name_enc));
	snprintf(dirname, sizeof(dirname), "%s/.udev/links/%s", udev_get_dev_path(udev), name_enc);
	snprintf(filename, sizeof(filename), "%s/%c%u:%u", dirname,
		 strcmp(udev_device_get_subsystem(dev), "block") == 0 ? 'b' : 'c',
		 major(udev_device_get_devnum(dev)), minor(udev_device_get_devnum(dev)));

	if (!add) {
		dbg(udev, "removing index: '%s'\n", filename);
		unlink(filename);
		util_delete_path(udev, filename);
	}

	target = link_find_prioritized(dev, add, dirname, buf, sizeof(buf));
	if (target == NULL) {
		info(udev, "no reference left, remove '%s'\n", slink);
		unlink(slink);
		util_delete_path(udev, slink);
	} else {
		info(udev, "creating link '%s' to '%s'\n", slink, target);
		node_symlink(udev, target, slink);
	}

	if (add) {
		int err;

		dbg(udev, "creating index: '%s'\n", filename);
		do {
			err = util_create_path(udev, filename);
			if (err != 0 && err != -ENOENT)
				break;
			err = symlink(udev_device_get_devpath(dev), filename);
			if (err != 0)
				err = -errno;
		} while (err == -ENOENT);
	}
}

void udev_node_update_old_links(struct udev_device *dev, struct udev_device *dev_old)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct udev_list_entry *list_entry;

	/* update possible left-over symlinks */
	udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev_old)) {
		const char *name = udev_list_entry_get_name(list_entry);
		struct udev_list_entry *list_entry_current;
		int found;

		/* check if old link name still belongs to this device */
		found = 0;
		udev_list_entry_foreach(list_entry_current, udev_device_get_devlinks_list_entry(dev)) {
			const char *name_current = udev_list_entry_get_name(list_entry_current);

			if (strcmp(name, name_current) == 0) {
				found = 1;
				break;
			}
		}
		if (found)
			continue;

		info(udev, "update old name, '%s' no longer belonging to '%s'\n",
		     name, udev_device_get_devpath(dev));
		link_update(dev, name, 0);
	}
}

int udev_node_add(struct udev_device *dev, mode_t mode, uid_t uid, gid_t gid)
{
	struct udev *udev = udev_device_get_udev(dev);
	int i;
	int num;
	struct udev_list_entry *list_entry;
	int err = 0;

	info(udev, "creating device node '%s', devnum=%d:%d, mode=%#o, uid=%d, gid=%d\n",
	     udev_device_get_devnode(dev),
	     major(udev_device_get_devnum(dev)), minor(udev_device_get_devnum(dev)),
	     mode, uid, gid);

	if (udev_node_mknod(dev, NULL, makedev(0,0), mode, uid, gid) != 0) {
		err = -1;
		goto exit;
	}

	/* create all_partitions if requested */
	num = udev_device_get_num_fake_partitions(dev);
	if (num > 0) {
		info(udev, "creating device partition nodes '%s[1-%i]'\n", udev_device_get_devnode(dev), num);
		for (i = 1; i <= num; i++) {
			char partitionname[UTIL_PATH_SIZE];
			dev_t part_devnum;

			snprintf(partitionname, sizeof(partitionname), "%s%d",
				 udev_device_get_devnode(dev), i);
			partitionname[sizeof(partitionname)-1] = '\0';
			part_devnum = makedev(major(udev_device_get_devnum(dev)),
					    minor(udev_device_get_devnum(dev)) + i);
			udev_node_mknod(dev, partitionname, part_devnum, mode, uid, gid);
		}
	}

	/* create/update symlinks, add symlinks to name index */
	udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev)) {
		if (udev_list_entry_get_flag(list_entry))
			/* simple unmanaged link name */
			node_symlink(udev, udev_device_get_devnode(dev), udev_list_entry_get_name(list_entry));
		else
			link_update(dev, udev_list_entry_get_name(list_entry), 1);
	}
exit:
	return err;
}

int udev_node_remove(struct udev_device *dev)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct udev_list_entry *list_entry;
	const char *devnode;
	char partitionname[UTIL_PATH_SIZE];
	struct stat stats;
	int err = 0;
	int num;

	/* remove,update symlinks, remove symlinks from name index */
	udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev))
		link_update(dev, udev_list_entry_get_name(list_entry), 0);

	devnode = udev_device_get_devnode(dev);
	if (devnode == NULL)
		return 0;
	if (stat(devnode, &stats) != 0) {
		info(udev, "device node '%s' not found\n", devnode);
		return 0;
	}
	if (stats.st_rdev != udev_device_get_devnum(dev)) {
		info(udev, "device node '%s' points to a different device, skip removal\n", devnode);
		return -1;
	}

	info(udev, "removing device node '%s'\n", devnode);
	err = util_unlink_secure(udev, devnode);
	if (err)
		return err;

	num = udev_device_get_num_fake_partitions(dev);
	if (num > 0) {
		int i;

		info(udev, "removing all_partitions '%s[1-%i]'\n", devnode, num);
		if (num > 255)
			return -1;
		for (i = 1; i <= num; i++) {
			snprintf(partitionname, sizeof(partitionname), "%s%d", devnode, i);
			partitionname[sizeof(partitionname)-1] = '\0';
			util_unlink_secure(udev, partitionname);
		}
	}
	util_delete_path(udev, devnode);
	return err;
}
