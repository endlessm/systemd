/*
 * Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2004 Chris Friesen <chris_friesen@sympatico.ca>
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
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include <getopt.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/netlink.h>
#ifdef HAVE_INOTIFY
#include <sys/inotify.h>
#endif

#include "udev.h"
#include "udev_rules.h"

#define UDEVD_PRIORITY			-4
#define UDEV_PRIORITY			-2

/* maximum limit of forked childs */
#define UDEVD_MAX_CHILDS		256

static int debug;

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	if (debug) {
		fprintf(stderr, "[%d] %s: ", (int) getpid(), fn);
		vfprintf(stderr, format, args);
	} else {
		vsyslog(priority, format, args);
	}
}

struct udevd_uevent_msg {
	struct udev *udev;
	struct list_head node;
	pid_t pid;
	int exitstatus;
	time_t queue_time;
	char *action;
	char *devpath;
	char *subsystem;
	char *driver;
	dev_t devt;
	unsigned long long seqnum;
	char *devpath_old;
	char *physdevpath;
	unsigned int timeout;
	char *envp[UEVENT_NUM_ENVP+1];
	char envbuf[];
};

static int debug_trace;
static struct udev_rules rules;
static struct udev_ctrl *udev_ctrl;
static int uevent_netlink_sock = -1;
static int inotify_fd = -1;

static int signal_pipe[2] = {-1, -1};
static volatile int sigchilds_waiting;
static volatile int udev_exit;
static volatile int reload_config;
static int run_exec_q;
static int stop_exec_q;
static int max_childs;
static char udev_log_env[32];

static LIST_HEAD(exec_list);
static LIST_HEAD(running_list);

static void asmlinkage udev_event_sig_handler(int signum)
{
	if (signum == SIGALRM)
		exit(1);
}

static int udev_event_process(struct udevd_uevent_msg *msg)
{
	struct sigaction act;
	struct udevice *udevice;
	int i;
	int retval;

	/* set signal handlers */
	memset(&act, 0x00, sizeof(act));
	act.sa_handler = (void (*)(int)) udev_event_sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);

	/* reset to default */
	act.sa_handler = SIG_DFL;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);
	sigaction(SIGHUP, &act, NULL);

	/* trigger timeout to prevent hanging processes */
	alarm(UDEV_EVENT_TIMEOUT);

	/* reconstruct event environment from message */
	for (i = 0; msg->envp[i]; i++)
		putenv(msg->envp[i]);

	udevice = udev_device_init(msg->udev);
	if (udevice == NULL)
		return -1;
	util_strlcpy(udevice->action, msg->action, sizeof(udevice->action));
	sysfs_device_set_values(udevice->udev, udevice->dev, msg->devpath, msg->subsystem, msg->driver);
	udevice->devpath_old = msg->devpath_old;
	udevice->devt = msg->devt;

	retval = udev_device_event(&rules, udevice);

	/* rules may change/disable the timeout */
	if (udevice->event_timeout >= 0)
		alarm(udevice->event_timeout);

	/* run programs collected by RUN-key*/
	if (retval == 0 && !udevice->ignore_device && udev_get_run(msg->udev))
		retval = udev_rules_run(udevice);

	udev_device_cleanup(udevice);
	return retval;
}

enum event_state {
	EVENT_QUEUED,
	EVENT_FINISHED,
	EVENT_FAILED,
};

static void export_event_state(struct udevd_uevent_msg *msg, enum event_state state)
{
	char filename[PATH_SIZE];
	char filename_failed[PATH_SIZE];
	size_t start;

	/* location of queue file */
	snprintf(filename, sizeof(filename), "%s/.udev/queue/%llu", udev_get_dev_path(msg->udev), msg->seqnum);

	/* location of failed file */
	util_strlcpy(filename_failed, udev_get_dev_path(msg->udev), sizeof(filename_failed));
	util_strlcat(filename_failed, "/", sizeof(filename_failed));
	start = util_strlcat(filename_failed, ".udev/failed/", sizeof(filename_failed));
	util_strlcat(filename_failed, msg->devpath, sizeof(filename_failed));
	util_path_encode(&filename_failed[start], sizeof(filename_failed) - start);

	switch (state) {
	case EVENT_QUEUED:
		unlink(filename_failed);
		delete_path(msg->udev, filename_failed);
		create_path(msg->udev, filename);
		udev_selinux_setfscreatecon(msg->udev, filename, S_IFLNK);
		symlink(msg->devpath, filename);
		udev_selinux_resetfscreatecon(msg->udev);
		break;
	case EVENT_FINISHED:
		if (msg->devpath_old != NULL) {
			/* "move" event - rename failed file to current name, do not delete failed */
			char filename_failed_old[PATH_SIZE];

			util_strlcpy(filename_failed_old, udev_get_dev_path(msg->udev), sizeof(filename_failed_old));
			util_strlcat(filename_failed_old, "/", sizeof(filename_failed_old));
			start = util_strlcat(filename_failed_old, ".udev/failed/", sizeof(filename_failed_old));
			util_strlcat(filename_failed_old, msg->devpath_old, sizeof(filename_failed_old));
			util_path_encode(&filename_failed_old[start], sizeof(filename) - start);

			if (rename(filename_failed_old, filename_failed) == 0)
				info(msg->udev, "renamed devpath, moved failed state of '%s' to %s'\n",
				     msg->devpath_old, msg->devpath);
		} else {
			unlink(filename_failed);
			delete_path(msg->udev, filename_failed);
		}

		unlink(filename);
		delete_path(msg->udev, filename);
		break;
	case EVENT_FAILED:
		/* move failed event to the failed directory */
		create_path(msg->udev, filename_failed);
		rename(filename, filename_failed);

		/* clean up possibly empty queue directory */
		delete_path(msg->udev, filename);
		break;
	}

	return;
}

static void msg_queue_delete(struct udevd_uevent_msg *msg)
{
	list_del(&msg->node);

	/* mark as failed, if "add" event returns non-zero */
	if (msg->exitstatus && strcmp(msg->action, "add") == 0)
		export_event_state(msg, EVENT_FAILED);
	else
		export_event_state(msg, EVENT_FINISHED);

	free(msg);
}

static void udev_event_run(struct udevd_uevent_msg *msg)
{
	pid_t pid;
	int retval;

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		close(uevent_netlink_sock);
		udev_ctrl_unref(udev_ctrl);
		if (inotify_fd >= 0)
			close(inotify_fd);
		close(signal_pipe[READ_END]);
		close(signal_pipe[WRITE_END]);
		logging_close();
		logging_init("udevd-event");
		setpriority(PRIO_PROCESS, 0, UDEV_PRIORITY);

		retval = udev_event_process(msg);
		info(msg->udev, "seq %llu finished with %i\n", msg->seqnum, retval);

		logging_close();
		if (retval)
			exit(1);
		exit(0);
	case -1:
		err(msg->udev, "fork of child failed: %s\n", strerror(errno));
		msg_queue_delete(msg);
		break;
	default:
		/* get SIGCHLD in main loop */
		info(msg->udev, "seq %llu forked, pid [%d], '%s' '%s', %ld seconds old\n",
		     msg->seqnum, pid,  msg->action, msg->subsystem, time(NULL) - msg->queue_time);
		msg->pid = pid;
	}
}

static void msg_queue_insert(struct udevd_uevent_msg *msg)
{
	char filename[PATH_SIZE];
	int fd;

	msg->queue_time = time(NULL);

	export_event_state(msg, EVENT_QUEUED);
	info(msg->udev, "seq %llu queued, '%s' '%s'\n", msg->seqnum, msg->action, msg->subsystem);

	util_strlcpy(filename, udev_get_dev_path(msg->udev), sizeof(filename));
	util_strlcat(filename, "/.udev/uevent_seqnum", sizeof(filename));
	fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if (fd >= 0) {
		char str[32];
		int len;

		len = sprintf(str, "%llu\n", msg->seqnum);
		write(fd, str, len);
		close(fd);
	}

	/* run one event after the other in debug mode */
	if (debug_trace) {
		list_add_tail(&msg->node, &running_list);
		udev_event_run(msg);
		waitpid(msg->pid, NULL, 0);
		msg_queue_delete(msg);
		return;
	}

	/* run all events with a timeout set immediately */
	if (msg->timeout != 0) {
		list_add_tail(&msg->node, &running_list);
		udev_event_run(msg);
		return;
	}

	list_add_tail(&msg->node, &exec_list);
	run_exec_q = 1;
}

static int mem_size_mb(void)
{
	FILE* f;
	char buf[4096];
	long int memsize = -1;

	f = fopen("/proc/meminfo", "r");
	if (f == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		long int value;

		if (sscanf(buf, "MemTotal: %ld kB", &value) == 1) {
			memsize = value / 1024;
			break;
		}
	}

	fclose(f);
	return memsize;
}

static int compare_devpath(const char *running, const char *waiting)
{
	int i;

	for (i = 0; i < PATH_SIZE; i++) {
		/* identical device event found */
		if (running[i] == '\0' && waiting[i] == '\0')
			return 1;

		/* parent device event found */
		if (running[i] == '\0' && waiting[i] == '/')
			return 2;

		/* child device event found */
		if (running[i] == '/' && waiting[i] == '\0')
			return 3;

		/* no matching event */
		if (running[i] != waiting[i])
			break;
	}

	return 0;
}

/* lookup event for identical, parent, child, or physical device */
static int devpath_busy(struct udevd_uevent_msg *msg, int limit)
{
	struct udevd_uevent_msg *loop_msg;
	int childs_count = 0;

	/* check exec-queue which may still contain delayed events we depend on */
	list_for_each_entry(loop_msg, &exec_list, node) {
		/* skip ourself and all later events */
		if (loop_msg->seqnum >= msg->seqnum)
			break;

		/* check our old name */
		if (msg->devpath_old != NULL)
			if (strcmp(loop_msg->devpath , msg->devpath_old) == 0)
				return 2;

		/* check identical, parent, or child device event */
		if (compare_devpath(loop_msg->devpath, msg->devpath) != 0) {
			dbg(msg->udev, "%llu, device event still pending %llu (%s)\n",
			    msg->seqnum, loop_msg->seqnum, loop_msg->devpath);
			return 3;
		}

		/* check for our major:minor number */
		if (msg->devt && loop_msg->devt == msg->devt &&
		    strcmp(msg->subsystem, loop_msg->subsystem) == 0) {
			dbg(msg->udev, "%llu, device event still pending %llu (%d:%d)\n", msg->seqnum,
			    loop_msg->seqnum, major(loop_msg->devt), minor(loop_msg->devt));
			return 4;
		}

		/* check physical device event (special case of parent) */
		if (msg->physdevpath && msg->action && strcmp(msg->action, "add") == 0)
			if (compare_devpath(loop_msg->devpath, msg->physdevpath) != 0) {
				dbg(msg->udev, "%llu, physical device event still pending %llu (%s)\n",
				    msg->seqnum, loop_msg->seqnum, loop_msg->devpath);
				return 5;
			}
	}

	/* check run queue for still running events */
	list_for_each_entry(loop_msg, &running_list, node) {
		childs_count++;

		if (childs_count++ >= limit) {
			info(msg->udev, "%llu, maximum number (%i) of childs reached\n", msg->seqnum, childs_count);
			return 1;
		}

		/* check our old name */
		if (msg->devpath_old != NULL)
			if (strcmp(loop_msg->devpath , msg->devpath_old) == 0)
				return 2;

		/* check identical, parent, or child device event */
		if (compare_devpath(loop_msg->devpath, msg->devpath) != 0) {
			dbg(msg->udev, "%llu, device event still running %llu (%s)\n",
			    msg->seqnum, loop_msg->seqnum, loop_msg->devpath);
			return 3;
		}

		/* check for our major:minor number */
		if (msg->devt && loop_msg->devt == msg->devt &&
		    strcmp(msg->subsystem, loop_msg->subsystem) == 0) {
			dbg(msg->udev, "%llu, device event still running %llu (%d:%d)\n", msg->seqnum,
			    loop_msg->seqnum, major(loop_msg->devt), minor(loop_msg->devt));
			return 4;
		}

		/* check physical device event (special case of parent) */
		if (msg->physdevpath && msg->action && strcmp(msg->action, "add") == 0)
			if (compare_devpath(loop_msg->devpath, msg->physdevpath) != 0) {
				dbg(msg->udev, "%llu, physical device event still running %llu (%s)\n",
				    msg->seqnum, loop_msg->seqnum, loop_msg->devpath);
				return 5;
			}
	}
	return 0;
}

/* serializes events for the identical and parent and child devices */
static void msg_queue_manager(struct udev *udev)
{
	struct udevd_uevent_msg *loop_msg;
	struct udevd_uevent_msg *tmp_msg;

	if (list_empty(&exec_list))
		return;

	list_for_each_entry_safe(loop_msg, tmp_msg, &exec_list, node) {
		/* serialize and wait for parent or child events */
		if (devpath_busy(loop_msg, max_childs) != 0) {
			dbg(udev, "delay seq %llu (%s)\n", loop_msg->seqnum, loop_msg->devpath);
			continue;
		}

		/* move event to run list */
		list_move_tail(&loop_msg->node, &running_list);
		udev_event_run(loop_msg);
		dbg(udev, "moved seq %llu to running list\n", loop_msg->seqnum);
	}
}

static struct udevd_uevent_msg *get_msg_from_envbuf(struct udev *udev, const char *buf, int buf_size)
{
	int bufpos;
	int i;
	struct udevd_uevent_msg *msg;
	char *physdevdriver_key = NULL;
	int maj = 0;
	int min = 0;

	msg = malloc(sizeof(struct udevd_uevent_msg) + buf_size);
	if (msg == NULL)
		return NULL;
	memset(msg, 0x00, sizeof(struct udevd_uevent_msg) + buf_size);
	msg->udev = udev;

	/* copy environment buffer and reconstruct envp */
	memcpy(msg->envbuf, buf, buf_size);
	bufpos = 0;
	for (i = 0; (bufpos < buf_size) && (i < UEVENT_NUM_ENVP-2); i++) {
		int keylen;
		char *key;

		key = &msg->envbuf[bufpos];
		keylen = strlen(key);
		msg->envp[i] = key;
		bufpos += keylen + 1;
		dbg(udev, "add '%s' to msg.envp[%i]\n", msg->envp[i], i);

		/* remember some keys for further processing */
		if (strncmp(key, "ACTION=", 7) == 0)
			msg->action = &key[7];
		else if (strncmp(key, "DEVPATH=", 8) == 0)
			msg->devpath = &key[8];
		else if (strncmp(key, "SUBSYSTEM=", 10) == 0)
			msg->subsystem = &key[10];
		else if (strncmp(key, "DRIVER=", 7) == 0)
			msg->driver = &key[7];
		else if (strncmp(key, "SEQNUM=", 7) == 0)
			msg->seqnum = strtoull(&key[7], NULL, 10);
		else if (strncmp(key, "DEVPATH_OLD=", 12) == 0)
			msg->devpath_old = &key[12];
		else if (strncmp(key, "PHYSDEVPATH=", 12) == 0)
			msg->physdevpath = &key[12];
		else if (strncmp(key, "PHYSDEVDRIVER=", 14) == 0)
			physdevdriver_key = key;
		else if (strncmp(key, "MAJOR=", 6) == 0)
			maj = strtoull(&key[6], NULL, 10);
		else if (strncmp(key, "MINOR=", 6) == 0)
			min = strtoull(&key[6], NULL, 10);
		else if (strncmp(key, "TIMEOUT=", 8) == 0)
			msg->timeout = strtoull(&key[8], NULL, 10);
	}
	msg->devt = makedev(maj, min);
	msg->envp[i++] = "UDEVD_EVENT=1";

	if (msg->driver == NULL && msg->physdevpath == NULL && physdevdriver_key != NULL) {
		/* for older kernels DRIVER is empty for a bus device, export PHYSDEVDRIVER as DRIVER */
		msg->envp[i++] = &physdevdriver_key[7];
		msg->driver = &physdevdriver_key[14];
	}

	msg->envp[i] = NULL;

	if (msg->devpath == NULL || msg->action == NULL) {
		info(udev, "DEVPATH or ACTION missing, ignore message\n");
		free(msg);
		return NULL;
	}
	return msg;
}

/* receive the udevd message from userspace */
static void handle_ctrl_msg(struct udev_ctrl *uctrl)
{
	struct udev *udev = udev_ctrl_get_udev(uctrl);
	struct udev_ctrl_msg *ctrl_msg;
	const char *str;
	int i;

	ctrl_msg = udev_ctrl_receive_msg(uctrl);
	if (ctrl_msg == NULL)
		return;

	i = udev_ctrl_get_set_log_level(ctrl_msg);
	if (i >= 0) {
		info(udev, "udevd message (SET_LOG_PRIORITY) received, log_priority=%i\n", i);
		udev_set_log_priority(udev, i);
		sprintf(udev_log_env, "UDEV_LOG=%i", i);
		putenv(udev_log_env);
	}

	if (udev_ctrl_get_stop_exec_queue(ctrl_msg) > 0) {
		info(udev, "udevd message (STOP_EXEC_QUEUE) received\n");
		stop_exec_q = 1;
	}

	if (udev_ctrl_get_start_exec_queue(ctrl_msg) > 0) {
		info(udev, "udevd message (START_EXEC_QUEUE) received\n");
		stop_exec_q = 0;
		msg_queue_manager(udev);
	}

	if (udev_ctrl_get_reload_rules(ctrl_msg) > 0) {
		info(udev, "udevd message (RELOAD_RULES) received\n");
		reload_config = 1;
	}

	str = udev_ctrl_get_set_env(ctrl_msg);
	if (str != NULL) {
		char *key = strdup(str);
		char *val;

		val = strchr(str, '=');
		if (val != NULL) {
			val[0] = '\0';
			val = &val[1];
			if (val[0] == '\0') {
				info(udev, "udevd message (ENV) received, unset '%s'\n", key);
				unsetenv(str);
			} else {
				info(udev, "udevd message (ENV) received, set '%s=%s'\n", key, val);
				setenv(key, val, 1);
			}
		} else {
			err(udev, "wrong key format '%s'\n", key);
		}
		free(key);
	}

	i = udev_ctrl_get_set_max_childs(ctrl_msg);
	if (i >= 0) {
		info(udev, "udevd message (SET_MAX_CHILDS) received, max_childs=%i\n", i);
		max_childs = i;
	}

	udev_ctrl_msg_unref(ctrl_msg);
}

/* receive the kernel user event message and do some sanity checks */
static struct udevd_uevent_msg *get_netlink_msg(struct udev *udev)
{
	struct udevd_uevent_msg *msg;
	int bufpos;
	ssize_t size;
	static char buffer[UEVENT_BUFFER_SIZE+512];
	char *pos;

	size = recv(uevent_netlink_sock, &buffer, sizeof(buffer), 0);
	if (size <  0) {
		if (errno != EINTR)
			err(udev, "unable to receive kernel netlink message: %s\n", strerror(errno));
		return NULL;
	}

	if ((size_t)size > sizeof(buffer)-1)
		size = sizeof(buffer)-1;
	buffer[size] = '\0';
	dbg(udev, "uevent_size=%zi\n", size);

	/* start of event payload */
	bufpos = strlen(buffer)+1;
	msg = get_msg_from_envbuf(udev, &buffer[bufpos], size-bufpos);
	if (msg == NULL)
		return NULL;

	/* validate message */
	pos = strchr(buffer, '@');
	if (pos == NULL) {
		err(udev, "invalid uevent '%s'\n", buffer);
		free(msg);
		return NULL;
	}
	pos[0] = '\0';

	if (msg->action == NULL) {
		info(udev, "no ACTION in payload found, skip event '%s'\n", buffer);
		free(msg);
		return NULL;
	}

	if (strcmp(msg->action, buffer) != 0) {
		err(udev, "ACTION in payload does not match uevent, skip event '%s'\n", buffer);
		free(msg);
		return NULL;
	}

	return msg;
}

static void asmlinkage sig_handler(int signum)
{
	switch (signum) {
		case SIGINT:
		case SIGTERM:
			udev_exit = 1;
			break;
		case SIGCHLD:
			/* set flag, then write to pipe if needed */
			sigchilds_waiting = 1;
			break;
		case SIGHUP:
			reload_config = 1;
			break;
	}

	/* write to pipe, which will wakeup select() in our mainloop */
	write(signal_pipe[WRITE_END], "", 1);
}

static void udev_done(int pid, int exitstatus)
{
	/* find msg associated with pid and delete it */
	struct udevd_uevent_msg *msg;

	list_for_each_entry(msg, &running_list, node) {
		if (msg->pid == pid) {
			info(msg->udev, "seq %llu, pid [%d] exit with %i, %ld seconds old\n", msg->seqnum, msg->pid,
			     exitstatus, time(NULL) - msg->queue_time);
			msg->exitstatus = exitstatus;
			msg_queue_delete(msg);

			/* there may be events waiting with the same devpath */
			run_exec_q = 1;
			return;
		}
	}
}

static void reap_sigchilds(void)
{
	pid_t pid;
	int status;

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid <= 0)
			break;
		if (WIFEXITED(status))
			status = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			status = WTERMSIG(status) + 128;
		else
			status = 0;
		udev_done(pid, status);
	}
}

static int init_uevent_netlink_sock(struct udev *udev)
{
	struct sockaddr_nl snl;
	const int buffersize = 16 * 1024 * 1024;
	int retval;

	memset(&snl, 0x00, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = getpid();
	snl.nl_groups = 1;

	uevent_netlink_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (uevent_netlink_sock == -1) {
		err(udev, "error getting socket: %s\n", strerror(errno));
		return -1;
	}

	/* set receive buffersize */
	setsockopt(uevent_netlink_sock, SOL_SOCKET, SO_RCVBUFFORCE, &buffersize, sizeof(buffersize));

	retval = bind(uevent_netlink_sock, (struct sockaddr *) &snl, sizeof(struct sockaddr_nl));
	if (retval < 0) {
		err(udev, "bind failed: %s\n", strerror(errno));
		close(uevent_netlink_sock);
		uevent_netlink_sock = -1;
		return -1;
	}
	return 0;
}

static void export_initial_seqnum(struct udev *udev)
{
	char filename[PATH_SIZE];
	int fd;
	char seqnum[32];
	ssize_t len = 0;

	util_strlcpy(filename, udev_get_sys_path(udev), sizeof(filename));
	util_strlcat(filename, "/kernel/uevent_seqnum", sizeof(filename));
	fd = open(filename, O_RDONLY);
	if (fd >= 0) {
		len = read(fd, seqnum, sizeof(seqnum)-1);
		close(fd);
	}
	if (len <= 0) {
		strcpy(seqnum, "0\n");
		len = 3;
	}
	util_strlcpy(filename, udev_get_dev_path(udev), sizeof(filename));
	util_strlcat(filename, "/.udev/uevent_seqnum", sizeof(filename));
	create_path(udev, filename);
	fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if (fd >= 0) {
		write(fd, seqnum, len);
		close(fd);
	}
}

int main(int argc, char *argv[])
{
	struct udev *udev;
	int retval;
	int fd;
	struct sigaction act;
	fd_set readfds;
	const char *value;
	int daemonize = 0;
	static const struct option options[] = {
		{ "daemon", 0, NULL, 'd' },
		{ "debug-trace", 0, NULL, 't' },
		{ "debug", 0, NULL, 'D' },
		{ "help", 0, NULL, 'h' },
		{ "version", 0, NULL, 'V' },
		{}
	};
	int rc = 1;
	int maxfd;

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	logging_init("udevd");
	udev_set_log_fn(udev, log_fn);
	dbg(udev, "version %s\n", VERSION);

	while (1) {
		int option;

		option = getopt_long(argc, argv, "dDthV", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			daemonize = 1;
			break;
		case 't':
			debug_trace = 1;
			break;
		case 'D':
			debug = 1;
			if (udev_get_log_priority(udev) < LOG_INFO)
				udev_set_log_priority(udev, LOG_INFO);
			break;
		case 'h':
			printf("Usage: udevd [--help] [--daemon] [--debug-trace] [--debug] [--version]\n");
			goto exit;
		case 'V':
			printf("%s\n", VERSION);
			goto exit;
		default:
			goto exit;
		}
	}

	if (getuid() != 0) {
		fprintf(stderr, "root privileges required\n");
		err(udev, "root privileges required\n");
		goto exit;
	}

	/* make sure std{in,out,err} fd's are in a sane state */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "cannot open /dev/null\n");
		err(udev, "cannot open /dev/null\n");
	}
	if (fd > STDIN_FILENO)
		dup2(fd, STDIN_FILENO);
	if (write(STDOUT_FILENO, 0, 0) < 0)
		dup2(fd, STDOUT_FILENO);
	if (write(STDERR_FILENO, 0, 0) < 0)
		dup2(fd, STDERR_FILENO);

	/* init control socket, bind() ensures, that only one udevd instance is running */
	udev_ctrl = udev_ctrl_new_from_socket(udev, UDEV_CTRL_SOCK_PATH);
	if (udev_ctrl == NULL) {
		fprintf(stderr, "error initializing control socket");
		err(udev, "error initializing udevd socket");
		rc = 1;
		goto exit;
	}

	if (udev_ctrl_enable_receiving(udev_ctrl) < 0) {
		fprintf(stderr, "error binding control socket, seems udevd is already running\n");
		err(udev, "error binding control socket, seems udevd is already running\n");
		rc = 1;
		goto exit;
	}

	if (init_uevent_netlink_sock(udev) < 0) {
		fprintf(stderr, "error initializing netlink socket\n");
		err(udev, "error initializing netlink socket\n");
		rc = 3;
		goto exit;
	}

	retval = pipe(signal_pipe);
	if (retval < 0) {
		err(udev, "error getting pipes: %s\n", strerror(errno));
		goto exit;
	}

	retval = fcntl(signal_pipe[READ_END], F_GETFL, 0);
	if (retval < 0) {
		err(udev, "error fcntl on read pipe: %s\n", strerror(errno));
		goto exit;
	}
	retval = fcntl(signal_pipe[READ_END], F_SETFL, retval | O_NONBLOCK);
	if (retval < 0) {
		err(udev, "error fcntl on read pipe: %s\n", strerror(errno));
		goto exit;
	}

	retval = fcntl(signal_pipe[WRITE_END], F_GETFL, 0);
	if (retval < 0) {
		err(udev, "error fcntl on write pipe: %s\n", strerror(errno));
		goto exit;
	}
	retval = fcntl(signal_pipe[WRITE_END], F_SETFL, retval | O_NONBLOCK);
	if (retval < 0) {
		err(udev, "error fcntl on write pipe: %s\n", strerror(errno));
		goto exit;
	}

	/* parse the rules and keep them in memory */
	sysfs_init();
	udev_rules_init(udev, &rules, 1);

	export_initial_seqnum(udev);

	if (daemonize) {
		pid_t pid;

		pid = fork();
		switch (pid) {
		case 0:
			dbg(udev, "daemonized fork running\n");
			break;
		case -1:
			err(udev, "fork of daemon failed: %s\n", strerror(errno));
			rc = 4;
			goto exit;
		default:
			dbg(udev, "child [%u] running, parent exits\n", pid);
			rc = 0;
			goto exit;
		}
	}

	/* redirect std{out,err} */
	if (!debug) {
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
	}
	if (fd > STDERR_FILENO)
		close(fd);

	/* set scheduling priority for the daemon */
	setpriority(PRIO_PROCESS, 0, UDEVD_PRIORITY);

	chdir("/");
	umask(022);
	setsid();

	/* OOM_DISABLE == -17 */
	fd = open("/proc/self/oom_adj", O_RDWR);
	if (fd < 0)
		err(udev, "error disabling OOM: %s\n", strerror(errno));
	else {
		write(fd, "-17", 3);
		close(fd);
	}

	fd = open("/dev/kmsg", O_WRONLY);
	if (fd > 0) {
		const char *str = "<6>udevd version " VERSION " started\n";

		write(fd, str, strlen(str));
		close(fd);
	}

	/* set signal handlers */
	memset(&act, 0x00, sizeof(struct sigaction));
	act.sa_handler = (void (*)(int)) sig_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);
	sigaction(SIGHUP, &act, NULL);

	/* watch rules directory */
	inotify_fd = inotify_init();
	if (inotify_fd >= 0) {
		if (udev_get_rules_path(udev) != NULL) {
			inotify_add_watch(inotify_fd, udev_get_rules_path(udev),
					  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
		} else {
			char filename[PATH_MAX];

			inotify_add_watch(inotify_fd, UDEV_PREFIX "/lib/udev/rules.d",
					  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
			inotify_add_watch(inotify_fd, SYSCONFDIR "/udev/rules.d",
					  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);

			/* watch dynamic rules directory */
			util_strlcpy(filename, udev_get_dev_path(udev), sizeof(filename));
			util_strlcat(filename, "/.udev/rules.d", sizeof(filename));
			inotify_add_watch(inotify_fd, filename,
					  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
		}
	} else if (errno == ENOSYS)
		err(udev, "the kernel does not support inotify, udevd can't monitor rules file changes\n");
	else
		err(udev, "inotify_init failed: %s\n", strerror(errno));

	/* maximum limit of forked childs */
	value = getenv("UDEVD_MAX_CHILDS");
	if (value)
		max_childs = strtoul(value, NULL, 10);
	else {
		int memsize = mem_size_mb();
		if (memsize > 0)
			max_childs = 128 + (memsize / 4);
		else
			max_childs = UDEVD_MAX_CHILDS;
	}
	info(udev, "initialize max_childs to %u\n", max_childs);

	/* clear environment for forked event processes */
	clearenv();

	/* export log_priority , as called programs may want to follow that setting */
	sprintf(udev_log_env, "UDEV_LOG=%i", udev_get_log_priority(udev));
	putenv(udev_log_env);
	if (debug_trace)
		putenv("DEBUG=1");

	maxfd = udev_ctrl_get_fd(udev_ctrl);
	maxfd = UDEV_MAX(maxfd, uevent_netlink_sock);
	maxfd = UDEV_MAX(maxfd, signal_pipe[READ_END]);
	maxfd = UDEV_MAX(maxfd, inotify_fd);

	while (!udev_exit) {
		struct udevd_uevent_msg *msg;
		int fdcount;

		FD_ZERO(&readfds);
		FD_SET(signal_pipe[READ_END], &readfds);
		FD_SET(udev_ctrl_get_fd(udev_ctrl), &readfds);
		FD_SET(uevent_netlink_sock, &readfds);
		if (inotify_fd >= 0)
			FD_SET(inotify_fd, &readfds);

		fdcount = select(maxfd+1, &readfds, NULL, NULL, NULL);
		if (fdcount < 0) {
			if (errno != EINTR)
				err(udev, "error in select: %s\n", strerror(errno));
			continue;
		}

		/* get control message */
		if (FD_ISSET(udev_ctrl_get_fd(udev_ctrl), &readfds))
			handle_ctrl_msg(udev_ctrl);

		/* get netlink message */
		if (FD_ISSET(uevent_netlink_sock, &readfds)) {
			msg = get_netlink_msg(udev);
			if (msg)
				msg_queue_insert(msg);
		}

		/* received a signal, clear our notification pipe */
		if (FD_ISSET(signal_pipe[READ_END], &readfds)) {
			char buf[256];

			read(signal_pipe[READ_END], &buf, sizeof(buf));
		}

		/* rules directory inotify watch */
		if ((inotify_fd >= 0) && FD_ISSET(inotify_fd, &readfds)) {
			int nbytes;

			/* discard all possible events, we can just reload the config */
			if ((ioctl(inotify_fd, FIONREAD, &nbytes) == 0) && nbytes > 0) {
				char *buf;

				reload_config = 1;
				buf = malloc(nbytes);
				if (buf == NULL) {
					err(udev, "error getting buffer for inotify, disable watching\n");
					close(inotify_fd);
					inotify_fd = -1;
				}
				read(inotify_fd, buf, nbytes);
				free(buf);
			}
		}

		/* rules changed, set by inotify or a HUP signal */
		if (reload_config) {
			reload_config = 0;
			udev_rules_cleanup(&rules);
			udev_rules_init(udev, &rules, 1);
		}

		/* forked child has returned */
		if (sigchilds_waiting) {
			sigchilds_waiting = 0;
			reap_sigchilds();
		}

		if (run_exec_q) {
			run_exec_q = 0;
			if (!stop_exec_q)
				msg_queue_manager(udev);
		}
	}
	rc = 0;

exit:
	udev_rules_cleanup(&rules);
	sysfs_cleanup();

	if (signal_pipe[READ_END] >= 0)
		close(signal_pipe[READ_END]);
	if (signal_pipe[WRITE_END] >= 0)
		close(signal_pipe[WRITE_END]);

	udev_ctrl_unref(udev_ctrl);
	if (inotify_fd >= 0)
		close(inotify_fd);
	if (uevent_netlink_sock >= 0)
		close(uevent_netlink_sock);

	logging_close();
	return rc;
}
