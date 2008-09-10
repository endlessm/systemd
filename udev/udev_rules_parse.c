/*
 * Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2008 Kay Sievers <kay.sievers@vrfy.org>
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

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "udev.h"
#include "udev_rules.h"


void udev_rules_iter_init(struct udev_rules_iter *iter, struct udev_rules *rules)
{
	dbg(iter->rules->udev, "bufsize=%zi\n", rules->bufsize);
	iter->rules = rules;
	iter->current = 0;
}

struct udev_rule *udev_rules_iter_next(struct udev_rules_iter *iter)
{
	struct udev_rules *rules;
	struct udev_rule *rule;

	rules = iter->rules;
	if (!rules)
		return NULL;

	dbg(iter->rules->udev, "current=%zi\n", iter->current);
	if (iter->current >= rules->bufsize) {
		dbg(iter->rules->udev, "no more rules\n");
		return NULL;
	}

	/* get next rule */
	rule = (struct udev_rule *) (rules->buf + iter->current);
	iter->current += sizeof(struct udev_rule) + rule->bufsize;

	return rule;
}

struct udev_rule *udev_rules_iter_label(struct udev_rules_iter *iter, const char *label)
{
	struct udev_rule *rule;
	struct udev_rules *rules = iter->rules;
	size_t start = iter->current;

next:
	dbg(iter->rules->udev, "current=%zi\n", iter->current);
	if (iter->current >= rules->bufsize) {
		err(rules->udev, "LABEL='%s' not found, GOTO will be ignored\n", label);
		iter->current = start;
		return NULL;
	}
	rule = (struct udev_rule *) (rules->buf + iter->current);

	if (strcmp(&rule->buf[rule->label.val_off], label) != 0) {
		dbg(rules->udev, "moving forward, looking for label '%s'\n", label);
		iter->current += sizeof(struct udev_rule) + rule->bufsize;
		goto next;
	}

	dbg(rules->udev, "found label '%s'\n", label);
	return rule;
}

static int get_key(struct udev_rules *rules, char **line, char **key, enum key_operation *operation, char **value)
{
	char *linepos;
	char *temp;

	linepos = *line;
	if (linepos == NULL && linepos[0] == '\0')
		return -1;

	/* skip whitespace */
	while (isspace(linepos[0]) || linepos[0] == ',')
		linepos++;

	/* get the key */
	if (linepos[0] == '\0')
		return -1;
	*key = linepos;

	while (1) {
		linepos++;
		if (linepos[0] == '\0')
			return -1;
		if (isspace(linepos[0]))
			break;
		if (linepos[0] == '=')
			break;
		if ((linepos[0] == '+') || (linepos[0] == '!') || (linepos[0] == ':'))
			if (linepos[1] == '=')
				break;
	}

	/* remember end of key */
	temp = linepos;

	/* skip whitespace after key */
	while (isspace(linepos[0]))
		linepos++;
	if (linepos[0] == '\0')
		return -1;

	/* get operation type */
	if (linepos[0] == '=' && linepos[1] == '=') {
		*operation = KEY_OP_MATCH;
		linepos += 2;
		dbg(rules->udev, "operator=match\n");
	} else if (linepos[0] == '!' && linepos[1] == '=') {
		*operation = KEY_OP_NOMATCH;
		linepos += 2;
		dbg(rules->udev, "operator=nomatch\n");
	} else if (linepos[0] == '+' && linepos[1] == '=') {
		*operation = KEY_OP_ADD;
		linepos += 2;
		dbg(rules->udev, "operator=add\n");
	} else if (linepos[0] == '=') {
		*operation = KEY_OP_ASSIGN;
		linepos++;
		dbg(rules->udev, "operator=assign\n");
	} else if (linepos[0] == ':' && linepos[1] == '=') {
		*operation = KEY_OP_ASSIGN_FINAL;
		linepos += 2;
		dbg(rules->udev, "operator=assign_final\n");
	} else
		return -1;

	/* terminate key */
	temp[0] = '\0';
	dbg(rules->udev, "key='%s'\n", *key);

	/* skip whitespace after operator */
	while (isspace(linepos[0]))
		linepos++;
	if (linepos[0] == '\0')
		return -1;

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
	temp++;
	dbg(rules->udev, "value='%s'\n", *value);

	/* move line to next key */
	*line = temp;

	return 0;
}

/* extract possible KEY{attr} */
static char *get_key_attribute(struct udev_rules *rules, char *str)
{
	char *pos;
	char *attr;

	attr = strchr(str, '{');
	if (attr != NULL) {
		attr++;
		pos = strchr(attr, '}');
		if (pos == NULL) {
			err(rules->udev, "missing closing brace for format\n");
			return NULL;
		}
		pos[0] = '\0';
		dbg(rules->udev, "attribute='%s'\n", attr);
		return attr;
	}

	return NULL;
}

static int add_rule_key(struct udev_rule *rule, struct key *key,
			enum key_operation operation, const char *value)
{
	size_t val_len = strnlen(value, PATH_SIZE);

	key->operation = operation;

	key->val_off = rule->bufsize;
	util_strlcpy(rule->buf + rule->bufsize, value, val_len+1);
	rule->bufsize += val_len+1;

	return 0;
}

static int add_rule_key_pair(struct udev_rules *rules, struct udev_rule *rule, struct key_pairs *pairs,
			     enum key_operation operation, const char *key, const char *value)
{
	size_t key_len = strnlen(key, PATH_SIZE);

	if (pairs->count >= PAIRS_MAX) {
		err(rules->udev, "skip, too many keys of the same type in a single rule\n");
		return -1;
	}

	add_rule_key(rule, &pairs->keys[pairs->count].key, operation, value);

	/* add the key-name of the pair */
	pairs->keys[pairs->count].key_name_off = rule->bufsize;
	util_strlcpy(rule->buf + rule->bufsize, key, key_len+1);
	rule->bufsize += key_len+1;

	pairs->count++;

	return 0;
}

static int add_to_rules(struct udev_rules *rules, char *line, const char *filename, unsigned int lineno)
{
	char buf[sizeof(struct udev_rule) + LINE_SIZE];
	struct udev_rule *rule;
	size_t rule_size;
	int valid;
	char *linepos;
	char *attr;
	size_t padding;
	int physdev = 0;
	int retval;

	memset(buf, 0x00, sizeof(buf));
	rule = (struct udev_rule *) buf;
	rule->event_timeout = -1;
	linepos = line;
	valid = 0;

	/* get all the keys */
	while (1) {
		char *key;
		char *value;
		enum key_operation operation = KEY_OP_UNSET;

		retval = get_key(rules, &linepos, &key, &operation, &value);
		if (retval)
			break;

		if (strcasecmp(key, "ACTION") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid ACTION operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->action, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DEVPATH") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid DEVPATH operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->devpath, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "KERNEL") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid KERNEL operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->kernel, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "SUBSYSTEM") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid SUBSYSTEM operation\n");
				goto invalid;
			}
			/* bus, class, subsystem events should all be the same */
			if (strcmp(value, "subsystem") == 0 ||
			    strcmp(value, "bus") == 0 ||
			    strcmp(value, "class") == 0) {
				if (strcmp(value, "bus") == 0 || strcmp(value, "class") == 0)
					err(rules->udev, "'%s' must be specified as 'subsystem' \n"
					    "please fix it in %s:%u", value, filename, lineno);
				add_rule_key(rule, &rule->subsystem, operation, "subsystem|class|bus");
			} else
				add_rule_key(rule, &rule->subsystem, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DRIVER") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid DRIVER operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->driver, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ATTR{", sizeof("ATTR{")-1) == 0) {
			attr = get_key_attribute(rules, key + sizeof("ATTR")-1);
			if (attr == NULL) {
				err(rules->udev, "error parsing ATTR attribute\n");
				goto invalid;
			}
			if (add_rule_key_pair(rules, rule, &rule->attr, operation, attr, value) != 0)
				goto invalid;
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "KERNELS") == 0 ||
		    strcasecmp(key, "ID") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid KERNELS operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->kernels, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "SUBSYSTEMS") == 0 ||
		    strcasecmp(key, "BUS") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid SUBSYSTEMS operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->subsystems, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DRIVERS") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid DRIVERS operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->drivers, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ATTRS{", sizeof("ATTRS{")-1) == 0 ||
		    strncasecmp(key, "SYSFS{", sizeof("SYSFS{")-1) == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid ATTRS operation\n");
				goto invalid;
			}
			attr = get_key_attribute(rules, key + sizeof("ATTRS")-1);
			if (attr == NULL) {
				err(rules->udev, "error parsing ATTRS attribute\n");
				goto invalid;
			}
			if (strncmp(attr, "device/", 7) == 0)
				err(rules->udev, "the 'device' link is deprecated and will be removed from a future kernel, \n"
				    "please fix it in %s:%u", filename, lineno);
			else if (strstr(attr, "../") != NULL)
				err(rules->udev, "do not reference parent sysfs directories directly, that may break with a future kernel, \n"
				    "please fix it in %s:%u", filename, lineno);
			if (add_rule_key_pair(rules, rule, &rule->attrs, operation, attr, value) != 0)
				goto invalid;
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ENV{", sizeof("ENV{")-1) == 0) {
			attr = get_key_attribute(rules, key + sizeof("ENV")-1);
			if (attr == NULL) {
				err(rules->udev, "error parsing ENV attribute\n");
				goto invalid;
			}
			if (strncmp(attr, "PHYSDEV", 7) == 0)
				physdev = 1;
			if (add_rule_key_pair(rules, rule, &rule->env, operation, attr, value) != 0)
				goto invalid;
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "PROGRAM") == 0) {
			add_rule_key(rule, &rule->program, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "RESULT") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid RESULT operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->result, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "IMPORT", sizeof("IMPORT")-1) == 0) {
			attr = get_key_attribute(rules, key + sizeof("IMPORT")-1);
			if (attr != NULL && strstr(attr, "program")) {
				dbg(rules->udev, "IMPORT will be executed\n");
				rule->import_type  = IMPORT_PROGRAM;
			} else if (attr != NULL && strstr(attr, "file")) {
				dbg(rules->udev, "IMPORT will be included as file\n");
				rule->import_type  = IMPORT_FILE;
			} else if (attr != NULL && strstr(attr, "parent")) {
				dbg(rules->udev, "IMPORT will include the parent values\n");
				rule->import_type = IMPORT_PARENT;
			} else {
				/* figure it out if it is executable */
				char file[PATH_SIZE];
				char *pos;
				struct stat statbuf;

				util_strlcpy(file, value, sizeof(file));
				pos = strchr(file, ' ');
				if (pos)
					pos[0] = '\0';

				/* allow programs in /lib/udev called without the path */
				if (strchr(file, '/') == NULL) {
					util_strlcpy(file, UDEV_PREFIX "/lib/udev/", sizeof(file));
					util_strlcat(file, value, sizeof(file));
					pos = strchr(file, ' ');
					if (pos)
						pos[0] = '\0';
				}

				dbg(rules->udev, "IMPORT auto mode for '%s'\n", file);
				if (!lstat(file, &statbuf) && (statbuf.st_mode & S_IXUSR)) {
					dbg(rules->udev, "IMPORT is executable, will be executed (autotype)\n");
					rule->import_type  = IMPORT_PROGRAM;
				} else {
					dbg(rules->udev, "IMPORT is not executable, will be included as file (autotype)\n");
					rule->import_type  = IMPORT_FILE;
				}
			}
			add_rule_key(rule, &rule->import, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "TEST", sizeof("TEST")-1) == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid TEST operation\n");
				goto invalid;
			}
			attr = get_key_attribute(rules, key + sizeof("TEST")-1);
			if (attr != NULL)
				rule->test_mode_mask = strtol(attr, NULL, 8);
			add_rule_key(rule, &rule->test, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "RUN", sizeof("RUN")-1) == 0) {
			attr = get_key_attribute(rules, key + sizeof("RUN")-1);
			if (attr != NULL) {
				if (strstr(attr, "ignore_error"))
					rule->run_ignore_error = 1;
			}
			add_rule_key(rule, &rule->run, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "WAIT_FOR") == 0 || strcasecmp(key, "WAIT_FOR_SYSFS") == 0) {
			add_rule_key(rule, &rule->wait_for, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "LABEL") == 0) {
			add_rule_key(rule, &rule->label, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "GOTO") == 0) {
			add_rule_key(rule, &rule->goto_label, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "NAME", sizeof("NAME")-1) == 0) {
			attr = get_key_attribute(rules, key + sizeof("NAME")-1);
			if (attr != NULL) {
				if (strstr(attr, "all_partitions") != NULL) {
					dbg(rules->udev, "creation of partition nodes requested\n");
					rule->partitions = DEFAULT_PARTITIONS_COUNT;
				}
				if (strstr(attr, "ignore_remove") != NULL) {
					dbg(rules->udev, "remove event should be ignored\n");
					rule->ignore_remove = 1;
				}
			}
			if (value[0] == '\0')
				dbg(rules->udev, "name empty, node creation supressed\n");
			add_rule_key(rule, &rule->name, operation, value);
			continue;
		}

		if (strcasecmp(key, "SYMLINK") == 0) {
			if (operation == KEY_OP_MATCH ||
			    operation == KEY_OP_NOMATCH)
				add_rule_key(rule, &rule->symlink_match, operation, value);
			else
				add_rule_key(rule, &rule->symlink, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "OWNER") == 0) {
			valid = 1;
			if (rules->resolve_names && (!strchr(value, '$') && !strchr(value, '%'))) {
				char *endptr;
				strtoul(value, &endptr, 10);
				if (endptr[0] != '\0') {
					char owner[32];
					uid_t uid = lookup_user(rules->udev, value);
					dbg(rules->udev, "replacing username='%s' by id=%i\n", value, uid);
					sprintf(owner, "%u", (unsigned int) uid);
					add_rule_key(rule, &rule->owner, operation, owner);
					continue;
				}
			}

			add_rule_key(rule, &rule->owner, operation, value);
			continue;
		}

		if (strcasecmp(key, "GROUP") == 0) {
			valid = 1;
			if (rules->resolve_names && (!strchr(value, '$') && !strchr(value, '%'))) {
				char *endptr;
				strtoul(value, &endptr, 10);
				if (endptr[0] != '\0') {
					char group[32];
					gid_t gid = lookup_group(rules->udev, value);
					dbg(rules->udev, "replacing groupname='%s' by id=%i\n", value, gid);
					sprintf(group, "%u", (unsigned int) gid);
					add_rule_key(rule, &rule->group, operation, group);
					continue;
				}
			}

			add_rule_key(rule, &rule->group, operation, value);
			continue;
		}

		if (strcasecmp(key, "MODE") == 0) {
			add_rule_key(rule, &rule->mode, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "OPTIONS") == 0) {
			const char *pos;

			if (strstr(value, "last_rule") != NULL) {
				dbg(rules->udev, "last rule to be applied\n");
				rule->last_rule = 1;
			}
			if (strstr(value, "ignore_device") != NULL) {
				dbg(rules->udev, "device should be ignored\n");
				rule->ignore_device = 1;
			}
			if (strstr(value, "ignore_remove") != NULL) {
				dbg(rules->udev, "remove event should be ignored\n");
				rule->ignore_remove = 1;
			}
			pos = strstr(value, "link_priority=");
			if (pos != NULL) {
				rule->link_priority = atoi(&pos[strlen("link_priority=")]);
				dbg(rules->udev, "link priority=%i\n", rule->link_priority);
			}
			pos = strstr(value, "event_timeout=");
			if (pos != NULL) {
				rule->event_timeout = atoi(&pos[strlen("event_timeout=")]);
				dbg(rules->udev, "event timout=%i\n", rule->event_timeout);
			}
			pos = strstr(value, "string_escape=");
			if (pos != NULL) {
				pos = &pos[strlen("string_escape=")];
				if (strncmp(pos, "none", strlen("none")) == 0)
					rule->string_escape = ESCAPE_NONE;
				else if (strncmp(pos, "replace", strlen("replace")) == 0)
					rule->string_escape = ESCAPE_REPLACE;
			}
			if (strstr(value, "all_partitions") != NULL) {
				dbg(rules->udev, "creation of partition nodes requested\n");
				rule->partitions = DEFAULT_PARTITIONS_COUNT;
			}
			valid = 1;
			continue;
		}

		err(rules->udev, "unknown key '%s' in %s:%u\n", key, filename, lineno);
	}

	if (physdev && rule->wait_for.operation == KEY_OP_UNSET)
		err(rules->udev, "PHYSDEV* values are deprecated and will be removed from a future kernel, \n"
		    "please fix it in %s:%u", filename, lineno);

	/* skip line if not any valid key was found */
	if (!valid)
		goto invalid;

	/* grow buffer and add rule */
	rule_size = sizeof(struct udev_rule) + rule->bufsize;
	padding = (sizeof(size_t) - rule_size % sizeof(size_t)) % sizeof(size_t);
	dbg(rules->udev, "add %zi padding bytes\n", padding);
	rule_size += padding;
	rule->bufsize += padding;

	rules->buf = realloc(rules->buf, rules->bufsize + rule_size);
	if (!rules->buf) {
		err(rules->udev, "realloc failed\n");
		goto exit;
	}
	dbg(rules->udev, "adding rule to offset %zi\n", rules->bufsize);
	memcpy(rules->buf + rules->bufsize, rule, rule_size);
	rules->bufsize += rule_size;
exit:
	return 0;

invalid:
	err(rules->udev, "invalid rule '%s:%u'\n", filename, lineno);
	return -1;
}

static int parse_file(struct udev_rules *rules, const char *filename)
{
	char line[LINE_SIZE];
	char *bufline;
	unsigned int lineno;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;
	int retval = 0;

	if (file_map(filename, &buf, &bufsize) != 0) {
		err(rules->udev, "can't open '%s' as rules file: %s\n", filename, strerror(errno));
		return -1;
	}
	info(rules->udev, "reading '%s' as rules file\n", filename);

	/* loop through the whole file */
	cur = 0;
	lineno = 0;
	while (cur < bufsize) {
		unsigned int i, j;

		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;
		lineno++;

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

		if (count >= sizeof(line)) {
			err(rules->udev, "line too long, rule skipped '%s:%u'\n", filename, lineno);
			continue;
		}

		/* skip backslash and newline from multiline rules */
		for (i = j = 0; i < count; i++) {
			if (bufline[i] == '\\' && bufline[i+1] == '\n')
				continue;

			line[j++] = bufline[i];
		}
		line[j] = '\0';

		dbg(rules->udev, "read '%s'\n", line);
		add_to_rules(rules, line, filename, lineno);
	}

	file_unmap(buf, bufsize);
	return retval;
}

int udev_rules_init(struct udev *udev, struct udev_rules *rules, int resolve_names)
{
	struct stat statbuf;
	char filename[PATH_MAX];
	LIST_HEAD(name_list);
	LIST_HEAD(sort_list);
	struct name_entry *name_loop, *name_tmp;
	struct name_entry *sort_loop, *sort_tmp;
	int retval = 0;

	memset(rules, 0x00, sizeof(struct udev_rules));
	rules->udev = udev;
	rules->resolve_names = resolve_names;

	if (udev_get_rules_path(udev) != NULL) {
		/* custom rules location for testing */
		add_matching_files(udev, &name_list, udev_get_rules_path(udev), ".rules");
	} else {
		/* read user/custom rules */
		add_matching_files(udev, &name_list, SYSCONFDIR "/udev/rules.d", ".rules");

		/* read dynamic/temporary rules */
		util_strlcpy(filename, udev_get_dev_path(udev), sizeof(filename));
		util_strlcat(filename, "/.udev/rules.d", sizeof(filename));
		if (stat(filename, &statbuf) != 0) {
			create_path(udev, filename);
			udev_selinux_setfscreatecon(udev, filename, S_IFDIR|0755);
			mkdir(filename, 0755);
			udev_selinux_resetfscreatecon(udev);
		}
		add_matching_files(udev, &sort_list, filename, ".rules");

		/* read default rules */
		add_matching_files(udev, &sort_list, UDEV_PREFIX "/lib/udev/rules.d", ".rules");

		/* sort all rules files by basename into list of files */
		list_for_each_entry_safe(sort_loop, sort_tmp, &sort_list, node) {
			const char *sort_base = strrchr(sort_loop->name, '/');

			if (sort_base == NULL)
				continue;

			list_for_each_entry_safe(name_loop, name_tmp, &name_list, node) {
				const char *name_base = strrchr(name_loop->name, '/');

				if (name_base == NULL)
					continue;

				if (strcmp(name_base, sort_base) == 0) {
					info(udev, "rule file '%s' already added, ignoring '%s'\n",
					     name_loop->name, sort_loop->name);
					list_del(&sort_loop->node);
					free(sort_loop);
					sort_loop = NULL;
					continue;
				}

				if (strcmp(name_base, sort_base) > 0)
					break;
			}
			if (sort_loop != NULL)
				list_move_tail(&sort_loop->node, &name_loop->node);
		}
	}

	/* parse list of files */
	list_for_each_entry_safe(name_loop, name_tmp, &name_list, node) {
		if (stat(name_loop->name, &statbuf) == 0) {
			if (statbuf.st_size)
				parse_file(rules, name_loop->name);
			else
				dbg(udev, "empty rules file '%s'\n", name_loop->name);
		} else
			err(udev, "could not read '%s': %s\n", name_loop->name, strerror(errno));
		list_del(&name_loop->node);
		free(name_loop);
	}

	return retval;
}

void udev_rules_cleanup(struct udev_rules *rules)
{
	if (rules->buf) {
		free(rules->buf);
		rules->buf = NULL;
	}
}

