/*
 * udev_config.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_utils.h"
#include "udev_version.h"
#include "logging.h"

/* global variables */
char sysfs_path[PATH_SIZE];
char udev_root[PATH_SIZE];
char udev_db_path[PATH_SIZE];
char udev_config_filename[PATH_SIZE];
char udev_rules_filename[PATH_SIZE];
int udev_log_priority;
int udev_dev_d;
int udev_hotplug_d;

static int string_is_true(const char *str)
{
	if (strcasecmp(str, "true") == 0)
		return 1;
	if (strcasecmp(str, "yes") == 0)
		return 1;
	if (strcasecmp(str, "1") == 0)
		return 1;
	return 0;
}

static int log_priority(const char *priority)
{
	char *endptr;
	int prio;

	prio = strtol(priority, &endptr, 10);
	if (endptr[0] == '\0')
		return prio;
	if (strncasecmp(priority, "err", 3) == 0)
		return LOG_ERR;
	if (strcasecmp(priority, "info") == 0)
		return LOG_INFO;
	if (strcasecmp(priority, "debug") == 0)
		return LOG_DEBUG;
	if (string_is_true(priority))
		return LOG_ERR;

	return 0;
}

static int get_key(char **line, char **key, char **value)
{
	char *linepos;
	char *temp;

	linepos = *line;
	if (!linepos)
		return -1;

	/* skip whitespace */
	while (isspace(linepos[0]))
		linepos++;

	/* get the key */
	*key = linepos;
	while (1) {
		linepos++;
		if (linepos[0] == '\0')
			return -1;
		if (isspace(linepos[0]))
			break;
		if (linepos[0] == '=')
			break;
	}

	/* terminate key */
	linepos[0] = '\0';
	linepos++;

	/* skip whitespace */
	while (isspace(linepos[0]))
		linepos++;

	/* get the value*/
	if (linepos[0] == '"')
		linepos++;
	else
		return -1;
	*value = linepos;

	temp = strchr(linepos, '"');
	if (!temp)
		return -1;
	temp[0] = '\0';

	return 0;
}

static int parse_config_file(void)
{
	char line[LINE_SIZE];
	char *bufline;
	char *linepos;
	char *variable;
	char *value;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;
	int lineno;
	int retval = 0;

	if (file_map(udev_config_filename, &buf, &bufsize) != 0) {
		err("can't open '%s' as config file", udev_config_filename);
		return -ENODEV;
	}

	/* loop through the whole file */
	lineno = 0;
	cur = 0;
	while (cur < bufsize) {
		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;
		lineno++;

		if (count >= sizeof(line)) {
			err("line too long, conf line skipped %s, line %d", udev_config_filename, lineno);
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

		strlcpy(line, bufline, count);

		linepos = line;
		retval = get_key(&linepos, &variable, &value);
		if (retval != 0) {
			err("error parsing %s, line %d:%d", udev_config_filename, lineno, (int) (linepos-line));
			continue;
		}

		if (strcasecmp(variable, "udev_root") == 0) {
			strlcpy(udev_root, value, sizeof(udev_root));
			remove_trailing_char(udev_root, '/');
			continue;
		}

		if (strcasecmp(variable, "udev_db") == 0) {
			strlcpy(udev_db_path, value, sizeof(udev_db_path));
			remove_trailing_char(udev_db_path, '/');
			continue;
		}

		if (strcasecmp(variable, "udev_rules") == 0) {
			strlcpy(udev_rules_filename, value, sizeof(udev_rules_filename));
			remove_trailing_char(udev_rules_filename, '/');
			continue;
		}

		if (strcasecmp(variable, "udev_log") == 0) {
			udev_log_priority = log_priority(value);
			continue;
		}
	}

	file_unmap(buf, bufsize);
	return retval;
}

void udev_init_config(void)
{
	const char *env;

	strcpy(udev_root, UDEV_ROOT);
	strcpy(udev_db_path, UDEV_DB);
	strcpy(udev_config_filename, UDEV_CONFIG_FILE);
	strcpy(udev_rules_filename, UDEV_RULES_FILE);
	udev_log_priority = LOG_ERR;
	udev_dev_d = 1;
	udev_hotplug_d = 1;
	sysfs_get_mnt_path(sysfs_path, sizeof(sysfs_path));

	env = getenv("UDEV_NO_DEVD");
	if (env && string_is_true(env))
		udev_dev_d = 0;

	env = getenv("UDEV_NO_HOTPLUGD");
	if (env && string_is_true(env))
		udev_hotplug_d = 0;

	env = getenv("UDEV_CONFIG_FILE");
	if (env) {
		strlcpy(udev_config_filename, env, sizeof(udev_config_filename));
		remove_trailing_char(udev_config_filename, '/');
	}

	parse_config_file();

	env = getenv("UDEV_LOG");
	if (env)
		udev_log_priority = log_priority(env);

	dbg("sysfs_path='%s'", sysfs_path);
	dbg("UDEV_CONFIG_FILE='%s'", udev_config_filename);
	dbg("udev_root='%s'", udev_root);
	dbg("udev_db='%s'", udev_db_path);
	dbg("udev_rules='%s'", udev_rules_filename);
	dbg("udev_log=%d", udev_log_priority);
}
