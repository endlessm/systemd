/*
 * namedev_parse.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifdef DEBUG
/* define this to enable parsing debugging also */
/* #define DEBUG_PARSER */
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_utils.h"
#include "logging.h"
#include "namedev.h"

LIST_HEAD(config_device_list);

static int add_config_dev(struct config_device *new_dev)
{
	struct config_device *tmp_dev;

	tmp_dev = malloc(sizeof(*tmp_dev));
	if (tmp_dev == NULL)
		return -ENOMEM;
	memcpy(tmp_dev, new_dev, sizeof(*tmp_dev));
	list_add_tail(&tmp_dev->node, &config_device_list);
	//dump_config_dev(tmp_dev);
	return 0;
}

void dump_config_dev(struct config_device *dev)
{
	dbg_parse("name='%s', symlink='%s', bus='%s', id='%s', "
		  "sysfs_file[0]='%s', sysfs_value[0]='%s', "
		  "kernel='%s', program='%s', result='%s'"
		  "owner='%s', group='%s', mode=%#o",
		  dev->name, dev->symlink, dev->bus, dev->id,
		  dev->sysfs_pair[0].file, dev->sysfs_pair[0].value,
		  dev->kernel, dev->program, dev->result,
		  dev->owner, dev->group, dev->mode);
}

void dump_config_dev_list(void)
{
	struct config_device *dev;

	list_for_each_entry(dev, &config_device_list, node)
		dump_config_dev(dev);
}

/* extract possible KEY{attr} */
static char *get_key_attribute(char *str)
{
	char *pos;
	char *attr;

	attr = strchr(str, '{');
	if (attr != NULL) {
		attr++;
		pos = strchr(attr, '}');
		if (pos == NULL) {
			dbg("missing closing brace for format");
			return NULL;
		}
		pos[0] = '\0';
		dbg("attribute='%s'", attr);
		return attr;
	}

	return NULL;
}

static int namedev_parse(struct udevice *udev, const char *filename)
{
	char line[LINE_SIZE];
	char *bufline;
	int lineno;
	char *temp;
	char *temp2;
	char *temp3;
	char *attr;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;
	int program_given = 0;
	int valid;
	int retval = 0;
	struct config_device dev;

	if (file_map(filename, &buf, &bufsize) == 0) {
		dbg("reading '%s' as rules file", filename);
	} else {
		dbg("can't open '%s' as rules file", filename);
		return -1;
	}

	/* loop through the whole file */
	cur = 0;
	lineno = 0;
	while (cur < bufsize) {
		unsigned int i, j;

		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;
		lineno++;

		if (count >= sizeof(line)) {
			info("line too long, rule skipped %s, line %d", filename, lineno);
			continue;
		}

		/* eat the whitespace */
		while ((count > 0) && isspace(bufline[0])) {
			bufline++;
			count--;
		}
		if (count == 0)
			continue;

		/* see if this is a comment */
		if (bufline[0] == COMMENT_CHARACTER)
			continue;

		/* skip backslash and newline from multi line rules */
		for (i = j = 0; i < count; i++) {
			if (bufline[i] == '\\' && bufline[i+1] == '\n')
				continue;

			line[j++] = bufline[i];
		}
		line[j] = '\0';
		dbg_parse("read '%s'", line);

		/* get all known keys */
		memset(&dev, 0x00, sizeof(struct config_device));
		temp = line;
		valid = 0;

		while (1) {
			retval = parse_get_pair(&temp, &temp2, &temp3);
			if (retval)
				break;

			if (strcasecmp(temp2, FIELD_KERNEL) == 0) {
				strlcpy(dev.kernel, temp3, sizeof(dev.kernel));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_SUBSYSTEM) == 0) {
				strlcpy(dev.subsystem, temp3, sizeof(dev.subsystem));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_BUS) == 0) {
				strlcpy(dev.bus, temp3, sizeof(dev.bus));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_ID) == 0) {
				strlcpy(dev.id, temp3, sizeof(dev.id));
				valid = 1;
				continue;
			}

			if (strncasecmp(temp2, FIELD_SYSFS, sizeof(FIELD_SYSFS)-1) == 0) {
				struct sysfs_pair *pair = &dev.sysfs_pair[0];
				int sysfs_pair_num = 0;

				/* find first unused pair */
				while (pair->file[0] != '\0') {
					++sysfs_pair_num;
					if (sysfs_pair_num >= MAX_SYSFS_PAIRS) {
						pair = NULL;
						break;
					}
					++pair;
				}
				if (pair) {
					attr = get_key_attribute(temp2 + sizeof(FIELD_SYSFS)-1);
					if (attr == NULL) {
						dbg("error parsing " FIELD_SYSFS " attribute");
						continue;
					}
					strlcpy(pair->file, attr, sizeof(pair->file));
					strlcpy(pair->value, temp3, sizeof(pair->value));
					valid = 1;
				}
				continue;
			}

			if (strcasecmp(temp2, FIELD_DRIVER) == 0) {
				strlcpy(dev.driver, temp3, sizeof(dev.driver));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_PROGRAM) == 0) {
				program_given = 1;
				strlcpy(dev.program, temp3, sizeof(dev.program));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_RESULT) == 0) {
				strlcpy(dev.result, temp3, sizeof(dev.result));
				valid = 1;
				continue;
			}

			if (strncasecmp(temp2, FIELD_NAME, sizeof(FIELD_NAME)-1) == 0) {
				attr = get_key_attribute(temp2 + sizeof(FIELD_NAME)-1);
				/* FIXME: remove old style options and make OPTIONS= mandatory */
				if (attr != NULL) {
					if (strstr(attr, OPTION_PARTITIONS) != NULL) {
						dbg_parse("creation of partition nodes requested");
						dev.partitions = DEFAULT_PARTITIONS_COUNT;
					}
					if (strstr(attr, OPTION_IGNORE_REMOVE) != NULL) {
						dbg_parse("remove event should be ignored");
						dev.ignore_remove = 1;
					}
				}
				if (temp3[0] != '\0')
					strlcpy(dev.name, temp3, sizeof(dev.name));
				else
					dev.ignore_device = 1;
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_SYMLINK) == 0) {
				strlcpy(dev.symlink, temp3, sizeof(dev.symlink));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_OWNER) == 0) {
				strlcpy(dev.owner, temp3, sizeof(dev.owner));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_GROUP) == 0) {
				strlcpy(dev.group, temp3, sizeof(dev.group));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_MODE) == 0) {
				dev.mode = strtol(temp3, NULL, 8);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_OPTIONS) == 0) {
				if (strstr(temp3, OPTION_IGNORE_DEVICE) != NULL) {
					dbg_parse("device should be ignored");
					dev.ignore_device = 1;
				}
				if (strstr(temp3, OPTION_IGNORE_REMOVE) != NULL) {
					dbg_parse("remove event should be ignored");
					dev.ignore_remove = 1;
				}
				if (strstr(temp3, OPTION_PARTITIONS) != NULL) {
					dbg_parse("creation of partition nodes requested");
					dev.partitions = DEFAULT_PARTITIONS_COUNT;
				}
				valid = 1;
				continue;
			}

			dbg("unknown type of field '%s'", temp2);
			goto error;
		}

		/* skip line if not any valid key was found */
		if (!valid)
			goto error;

		/* simple plausibility checks for given keys */
		if ((dev.sysfs_pair[0].file[0] == '\0') ^
		    (dev.sysfs_pair[0].value[0] == '\0')) {
			info("inconsistency in " FIELD_SYSFS " key");
			goto error;
		}

		if ((dev.result[0] != '\0') && (program_given == 0)) {
			info(FIELD_RESULT " is only useful when "
			     FIELD_PROGRAM " is called in any rule before");
			goto error;
		}

		dev.config_line = lineno;
		strlcpy(dev.config_file, filename, sizeof(dev.config_file));
		retval = add_config_dev(&dev);
		if (retval) {
			dbg("add_config_dev returned with error %d", retval);
			continue;
error:
			info("parse error %s, line %d:%d, rule skipped",
			     filename, lineno, (int) (temp - line));
		}
	}

	file_unmap(buf, bufsize);
	return retval;
}

int namedev_init(void)
{
	struct stat stats;
	int retval;

	if (stat(udev_rules_filename, &stats) != 0)
		return -1;

	if ((stats.st_mode & S_IFMT) != S_IFDIR)
		retval = namedev_parse(NULL, udev_rules_filename);
	else
		retval = call_foreach_file(namedev_parse, NULL, udev_rules_filename, RULEFILE_SUFFIX);

	return retval;
}

void namedev_close(void)
{
	struct config_device *dev;
	struct config_device *temp_dev;

	list_for_each_entry_safe(dev, temp_dev, &config_device_list, node) {
		list_del(&dev->node);
		free(dev);
	}
}

