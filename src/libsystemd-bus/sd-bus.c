/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <endian.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/poll.h>
#include <byteswap.h>

#include "util.h"
#include "macro.h"

#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-type.h"

#define WQUEUE_MAX 128

static void bus_free(sd_bus *b) {
        struct filter_callback *f;

        assert(b);

        if (b->fd >= 0)
                close_nointr_nofail(b->fd);

        free(b->rbuffer);
        free(b->rqueue);
        free(b->wqueue);
        free(b->unique_name);

        hashmap_free_free(b->reply_callbacks);

        while ((f = b->filter_callbacks)) {
                LIST_REMOVE(struct filter_callback, callbacks, b->filter_callbacks, f);
                free(f);
        }

        free(b);
}

static sd_bus* bus_new(void) {
        sd_bus *r;

        r = new0(sd_bus, 1);
        if (!r)
                return NULL;

        r->n_ref = 1;
        r->fd = -1;
        r->message_version = 1;

        /* We guarantee that wqueue always has space for at least one
         * entry */
        r->wqueue = new(sd_bus_message*, 1);
        if (!r->wqueue) {
                free(r);
                return NULL;
        }

        return r;
};

static int hello_callback(sd_bus *bus, sd_bus_message *reply, void *userdata) {
        const char *s;
        int r;

        assert(bus);
        assert(reply);

        bus->state = BUS_RUNNING;

        r = sd_bus_message_read(reply, "s", &s);
        if (r < 0)
                return r;

        bus->unique_name = strdup(s);
        if (!bus->unique_name)
                return -ENOMEM;

        return 1;
}

static int bus_send_hello(sd_bus *bus) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_method_call(
                        bus,
                        "org.freedesktop.DBus",
                        "/",
                        "org.freedesktop.DBus",
                        "Hello",
                        &m);
        if (r < 0)
                return r;

        r = sd_bus_send_with_reply(bus, m, hello_callback, NULL, (uint64_t) -1, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int bus_start_running(sd_bus *bus) {
        int r;

        assert(bus);

        if (bus->send_hello) {
                bus->state = BUS_HELLO;

                r = bus_send_hello(bus);
                if (r < 0)
                        return r;
        }

        bus->state = BUS_RUNNING;

        return 0;
}

static int parse_address_key(const char **p, const char *key, char **value) {
        size_t l, n = 0;
        const char *a;
        char *r = NULL;

        assert(p);
        assert(*p);
        assert(key);
        assert(value);

        l = strlen(key);
        if (!strncmp(*p, key, l) != 0)
                return 0;

        if ((*p)[l] != '=')
                return 0;

        if (*value)
                return -EINVAL;

        a = *p + l + 1;
        while (*a != ';' && *a != 0) {
                char c, *t;

                if (*a == '%') {
                        int x, y;

                        x = unhexchar(a[1]);
                        if (x < 0) {
                                free(r);
                                return x;
                        }

                        y = unhexchar(a[2]);
                        if (y < 0) {
                                free(r);
                                return y;
                        }

                        a += 3;
                        c = (char) ((x << 4) | y);
                } else
                        c = *a;

                t = realloc(r, n + 1);
                if (!t) {
                        free(r);
                        return -ENOMEM;
                }

                r = t;
                r[n++] = c;
        }

        *p = a;
        *value = r;
        return 1;
}

static void skip_address_key(const char **p) {
        assert(p);
        assert(*p);

        *p += strcspn(*p, ";");
}

static int bus_parse_next_address(sd_bus *b) {
        const char *a, *p;
        _cleanup_free_ char *guid = NULL;
        int r;

        assert(b);

        if (!b->address)
                return 0;
        if (b->address[b->address_index] == 0)
                return 0;

        a = b->address + b->address_index;

        zero(b->sockaddr);
        b->sockaddr_size = 0;
        b->peer = SD_ID128_NULL;

        if (startswith(a, "unix:")) {
                _cleanup_free_ char *path = NULL, *abstract = NULL;

                p = a + 5;
                while (*p != 0 && *p != ';') {
                        r = parse_address_key(&p, "guid", &guid);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                continue;

                        r = parse_address_key(&p, "path", &path);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                continue;

                        r = parse_address_key(&p, "abstract", &abstract);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                continue;

                        skip_address_key(&p);
                }

                if (!path && !abstract)
                        return -EINVAL;

                if (path && abstract)
                        return -EINVAL;

                if (path) {
                        size_t l;

                        l = strlen(path);
                        if (l > sizeof(b->sockaddr.un.sun_path))
                                return -E2BIG;

                        b->sockaddr.un.sun_family = AF_UNIX;
                        strncpy(b->sockaddr.un.sun_path, path, sizeof(b->sockaddr.un.sun_path));
                        b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + l;
                } else if (abstract) {
                        size_t l;

                        l = strlen(path);
                        if (l > sizeof(b->sockaddr.un.sun_path) - 1)
                                return -E2BIG;

                        b->sockaddr.un.sun_family = AF_UNIX;
                        b->sockaddr.un.sun_path[0] = 0;
                        strncpy(b->sockaddr.un.sun_path+1, path, sizeof(b->sockaddr.un.sun_path)-1);
                        b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + 1 + l;
                }

        } else if (startswith(a, "tcp:")) {
                _cleanup_free_ char *host = NULL, *port = NULL, *family = NULL;
                struct addrinfo hints, *result;

                p = a + 4;
                while (*p != 0 && *p != ';') {
                        r = parse_address_key(&p, "guid", &guid);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                continue;

                        r = parse_address_key(&p, "host", &host);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                continue;

                        r = parse_address_key(&p, "port", &port);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                continue;

                        r = parse_address_key(&p, "family", &family);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                continue;

                        skip_address_key(&p);
                }

                if (!host || !port)
                        return -EINVAL;

                zero(hints);
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_flags = AI_ADDRCONFIG;

                if (family) {
                        if (streq(family, "ipv4"))
                                hints.ai_family = AF_INET;
                        else if (streq(family, "ipv6"))
                                hints.ai_family = AF_INET6;
                        else
                                return -EINVAL;
                }

                r = getaddrinfo(host, port, &hints, &result);
                if (r == EAI_SYSTEM)
                        return -errno;
                else if (r != 0)
                        return -EADDRNOTAVAIL;

                memcpy(&b->sockaddr, result->ai_addr, result->ai_addrlen);
                b->sockaddr_size = result->ai_addrlen;

                freeaddrinfo(result);
        }

        if (guid) {
                r = sd_id128_from_string(guid, &b->peer);
                if (r < 0)
                        return r;
        }

        b->address_index = p - b->address;
        return 1;
}

static void iovec_advance(struct iovec *iov, unsigned *idx, size_t size) {

        while (size > 0) {
                struct iovec *i = iov + *idx;

                if (i->iov_len > size) {
                        i->iov_base = (uint8_t*) i->iov_base + size;
                        i->iov_len -= size;
                        return;
                }

                size -= i->iov_len;

                i->iov_base = NULL;
                i->iov_len = 0;

                (*idx) ++;
        }
}

static int bus_write_auth(sd_bus *b) {
        struct msghdr mh;
        ssize_t k;

        assert(b);
        assert(b->state == BUS_AUTHENTICATING);

        if (b->auth_index >= ELEMENTSOF(b->auth_iovec))
                return 0;

        zero(mh);
        mh.msg_iov = b->auth_iovec + b->auth_index;
        mh.msg_iovlen = ELEMENTSOF(b->auth_iovec) - b->auth_index;

        k = sendmsg(b->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;

        iovec_advance(b->auth_iovec, &b->auth_index, (size_t) k);

        return 1;
}

static int bus_auth_verify(sd_bus *b) {
        char *e, *f;
        sd_id128_t peer;
        unsigned i;
        int r;

        /* We expect two response lines: "OK", "AGREE_UNIX_FD", and
         * that's it */

        e = memmem(b->rbuffer, b->rbuffer_size, "\r\n", 2);
        if (!e)
                return 0;

        f = memmem(e, b->rbuffer_size - (e - (char*) b->rbuffer), "\r\n", 2);
        if (!f)
                return 0;

        if (e - (char*) b->rbuffer != 3 + 32)
                return -EPERM;

        if (memcmp(b->rbuffer, "OK ", 3))
                return -EPERM;

        for (i = 0; i < 32; i += 2) {
                int x, y;

                x = unhexchar(((char*) b->rbuffer)[3 + i]);
                y = unhexchar(((char*) b->rbuffer)[3 + i + 2]);

                if (x < 0 || y < 0)
                        return -EINVAL;

                peer.bytes[i/2] = ((uint8_t) x << 4 | (uint8_t) y);
        }

        if (!sd_id128_equal(b->peer, SD_ID128_NULL) &&
            !sd_id128_equal(b->peer, peer))
                return -EPERM;

        b->peer = peer;

        b->can_fds =
                (f - e == sizeof("\r\nAGREE_UNIX_FD") - 1) &&
                memcmp(e + 2, "AGREE_UNIX_FD", sizeof("AGREE_UNIX_FD") - 1) == 0;

        if (f + 2 > (char*) b->rbuffer + b->rbuffer_size) {
                b->rbuffer_size -= (f - (char*) b->rbuffer);
                memmove(b->rbuffer, f + 2, b->rbuffer_size);
        }

        r = bus_start_running(b);
        if (r < 0)
                return r;

        return 1;
}

static int bus_read_auth(sd_bus *b) {
        struct msghdr mh;
        struct iovec iov;
        size_t n;
        ssize_t k;
        int r;

        assert(b);

        r = bus_auth_verify(b);
        if (r != 0)
                return r;

        n = MAX(3 + 32 + 2 + sizeof("AGREE_UNIX_FD") - 1 + 2, b->rbuffer_size * 2);

        zero(iov);
        iov.iov_base = (uint8_t*) b->rbuffer + b->rbuffer_size;
        iov.iov_len = n - b->rbuffer_size;

        zero(mh);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

        k = recvmsg(b->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;

        b->rbuffer_size += k;

        r = bus_auth_verify(b);
        if (r != 0)
                return r;

        return 0;
}

static int bus_start_auth(sd_bus *b) {
        static const char auth_prefix[] = "\0AUTH_EXTERNAL ";
        static const char auth_suffix[] = "\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";

        char text[20 + 1]; /* enough space for a 64bit integer plus NUL */
        size_t l;

        assert(b);

        b->state = BUS_AUTHENTICATING;

        snprintf(text, sizeof(text), "%llu", (unsigned long long) geteuid());
        char_array_0(text);

        l = strlen(text);
        b->auth_uid = hexmem(text, l);
        if (!b->auth_uid)
                return -ENOMEM;

        b->auth_iovec[0].iov_base = (void*) auth_prefix;
        b->auth_iovec[0].iov_len = sizeof(auth_prefix) -1;
        b->auth_iovec[1].iov_base = (void*) b->auth_uid;
        b->auth_iovec[1].iov_len = l * 2;
        b->auth_iovec[2].iov_base = (void*) auth_suffix;
        b->auth_iovec[2].iov_len = sizeof(auth_suffix) -1;
        b->auth_size = sizeof(auth_prefix) - 1 + l * 2 + sizeof(auth_suffix) - 1;

        return bus_write_auth(b);
}

static int bus_start_connect(sd_bus *b) {
        int r;

        assert(b);
        assert(b->fd < 0);

        for (;;) {
                if (b->sockaddr.sa.sa_family == AF_UNSPEC) {
                        r = bus_parse_next_address(b);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return b->last_connect_error ? b->last_connect_error : -ECONNREFUSED;
                }

                b->fd = socket(b->sockaddr.sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (b->fd < 0) {
                        b->last_connect_error = -errno;
                        zero(b->sockaddr);
                        continue;
                }

                r = connect(b->fd, &b->sockaddr.sa, b->sockaddr_size);
                if (r < 0) {
                        if (errno == EINPROGRESS)
                                return 0;

                        b->last_connect_error = -errno;
                        close_nointr_nofail(b->fd);
                        b->fd = -1;
                        zero(b->sockaddr);
                        continue;
                }

                return bus_start_auth(b);
        }
}

int sd_bus_open_system(sd_bus **ret) {
        const char *e;
        sd_bus *b;
        int r;

        if (!ret)
                return -EINVAL;

        e = getenv("DBUS_SYSTEM_BUS_ADDRESS");
        if (e) {
                r = sd_bus_open_address(e, &b);
                if (r < 0)
                        return r;

                b->send_hello = true;
                *ret = b;
                return r;
        }

        b = bus_new();
        if (!b)
                return -ENOMEM;

        b->send_hello = true;

        b->sockaddr.un.sun_family = AF_UNIX;
        strncpy(b->sockaddr.un.sun_path, "/run/dbus/system_bus_socket", sizeof(b->sockaddr.un.sun_path));
        b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + sizeof("/run/dbus/system_bus_socket") - 1;

        r = bus_start_connect(b);
        if (r < 0) {
                bus_free(b);
                return r;
        }

        *ret = b;
        return 0;
}

int sd_bus_open_user(sd_bus **ret) {
        const char *e;
        sd_bus *b;
        size_t l;
        int r;

        if (!ret)
                return -EINVAL;

        e = getenv("DBUS_SESSION_BUS_ADDRESS");
        if (e) {
                r = sd_bus_open_address(e, &b);
                if (r < 0)
                        return r;

                b->send_hello = true;
                *ret = b;
                return r;
        }

        e = getenv("XDG_RUNTIME_DIR");
        if (!e)
                return -ENOENT;

        l = strlen(e);
        if (l + 4 > sizeof(b->sockaddr.un.sun_path))
                return -E2BIG;

        b = bus_new();
        if (!b)
                return -ENOMEM;

        b->send_hello = true;

        b->sockaddr.un.sun_family = AF_UNIX;
        memcpy(mempcpy(b->sockaddr.un.sun_path, e, l), "/bus", 4);
        b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + l + 4;

        r = bus_start_connect(b);
        if (r < 0) {
                bus_free(b);
                return r;
        }

        *ret = b;
        return 0;
}

int sd_bus_open_address(const char *address, sd_bus **ret) {
        sd_bus *b;
        int r;

        if (!address)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        b = bus_new();
        if (!b)
                return -ENOMEM;

        b->address = strdup(address);
        if (!b->address) {
                bus_free(b);
                return -ENOMEM;
        }

        r = bus_start_connect(b);
        if (r < 0) {
                bus_free(b);
                return r;
        }

        *ret = b;
        return 0;
}

int sd_bus_open_fd(int fd, sd_bus **ret) {
        sd_bus *b;
        int r;

        if (fd < 0)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        b = bus_new();
        if (!b)
                return -ENOMEM;

        b->fd = fd;
        fd_nonblock(b->fd, true);
        fd_cloexec(b->fd, true);

        r = bus_start_auth(b);
        if (r < 0) {
                bus_free(b);
                return r;
        }

        *ret = b;
        return 0;
}

void sd_bus_close(sd_bus *bus) {
        if (!bus)
                return;
        if (bus->fd < 0)
                return;

        close_nointr_nofail(bus->fd);
        bus->fd = -1;
}

sd_bus *sd_bus_ref(sd_bus *bus) {
        if (!bus)
                return NULL;

        assert(bus->n_ref > 0);

        bus->n_ref++;
        return bus;
}

sd_bus *sd_bus_unref(sd_bus *bus) {
        if (!bus)
                return NULL;

        assert(bus->n_ref > 0);
        bus->n_ref--;

        if (bus->n_ref <= 0)
                bus_free(bus);

        return NULL;
}

int sd_bus_is_running(sd_bus *bus) {
        if (!bus)
                return -EINVAL;

        if (bus->fd < 0)
                return -ENOTCONN;

        return bus->state == BUS_RUNNING;
}

int sd_bus_can_send(sd_bus *bus, char type) {

        if (!bus)
                return -EINVAL;

        if (type == SD_BUS_TYPE_UNIX_FD)
                return bus->can_fds;

        return bus_type_is_valid(type);
}

static int bus_seal_message(sd_bus *b, sd_bus_message *m) {
        assert(m);

        if (m->sealed)
                return 0;

        return message_seal(m, ++b->serial);
}

static int message_write(sd_bus *bus, sd_bus_message *m, size_t *idx) {
        struct msghdr mh;
        struct iovec *iov;
        ssize_t k;
        size_t n;
        unsigned j;

        assert(bus);
        assert(m);
        assert(idx);

        n = m->n_iovec * sizeof(struct iovec);
        iov = alloca(n);
        memcpy(iov, m->iovec, n);

        j = 0;
        iovec_advance(iov, &j, *idx);

        zero(mh);
        mh.msg_iov = iov;
        mh.msg_iovlen = m->n_iovec;

        k = sendmsg(bus->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return -errno;

        *idx += (size_t) k;
        iovec_advance(iov, &j, *idx);

        return j > m->n_iovec;
}

static int message_read_need(sd_bus *bus, size_t *need) {
        uint32_t a, b;
        uint8_t e;

        assert(bus);
        assert(need);

        if (bus->rbuffer_size <= sizeof(struct bus_header)) {
                *need = sizeof(struct bus_header);
                return 0;
        }

        a = ((const uint32_t*) bus->rbuffer)[1];
        b = ((const uint32_t*) bus->rbuffer)[3];

        e = ((const uint8_t*) bus->rbuffer)[0];
        if (e == SD_BUS_LITTLE_ENDIAN) {
                a = le32toh(a);
                b = le32toh(b);
        } else if (e == SD_BUS_BIG_ENDIAN) {
                a = be32toh(a);
                b = be32toh(b);
        } else
                return -EIO;

        *need = sizeof(struct bus_header) + ALIGN_TO(a, 8) + b;
        return 0;
}

static int message_make(sd_bus *bus, size_t size, sd_bus_message **m) {
        sd_bus_message *t;
        void *b = NULL;
        int r;

        assert(bus);
        assert(m);
        assert(bus->rbuffer_size >= size);

        t = new0(sd_bus_message, 1);
        if (!t)
                return -ENOMEM;

        if (bus->rbuffer_size > size) {
                b = memdup((const uint8_t*) bus->rbuffer + size, bus->rbuffer_size - size);
                if (!b) {
                        free(t);
                        return -ENOMEM;
                }
        }

        t->n_ref = 1;

        t->header = bus->rbuffer;
        t->free_header = true;

        t->fields = (uint8_t*) bus->rbuffer + sizeof(struct bus_header);
        t->body = (uint8_t*) bus->rbuffer + sizeof(struct bus_header) + ALIGN_TO(BUS_MESSAGE_BODY_SIZE(t), 8);

        bus->rbuffer = b;
        bus->rbuffer_size -= size;

        r = message_parse(t);
        if (r < 0) {
                sd_bus_message_unref(t);
                return r;
        }

        *m = t;
        return 1;
}

static int message_read(sd_bus *bus, sd_bus_message **m) {
        struct msghdr mh;
        struct iovec iov;
        ssize_t k;
        size_t need;
        int r;
        void *b;

        assert(bus);
        assert(m);

        r = message_read_need(bus, &need);
        if (r < 0)
                return r;

        if (bus->rbuffer_size >= need)
                return message_make(bus, need, m);

        b = realloc(bus->rbuffer, need);
        if (!b)
                return -ENOMEM;

        zero(iov);
        iov.iov_base = (uint8_t*) bus->rbuffer + bus->rbuffer_size;
        iov.iov_len = need - bus->rbuffer_size;

        zero(mh);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

        k = recvmsg(bus->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;

        bus->rbuffer_size += k;

        r = message_read_need(bus, &need);
        if (r < 0)
                return r;

        if (bus->rbuffer_size >= need)
                return message_make(bus, need, m);

        return 0;
}

static int dispatch_wqueue(sd_bus *bus) {
        int r, c = 0;

        assert(bus);

        if (bus->fd < 0)
                return -ENOTCONN;

        while (bus->wqueue_size > 0) {

                r = message_write(bus, bus->wqueue[0], &bus->windex);
                if (r < 0) {
                        sd_bus_close(bus);
                        return r;
                } else if (r == 0)
                        /* Wasn't fully written yet... */
                        break;
                else {
                        /* Fully written. Let's drop the entry from
                         * the queue.
                         *
                         * This isn't particularly optimized, but
                         * well, this is supposed to be our worst-case
                         * buffer only, and the socket buffer is
                         * supposed to be our primary buffer, and if
                         * it got full, then all bets are off
                         * anyway. */

                        sd_bus_message_unref(bus->wqueue[0]);
                        bus->wqueue_size --;
                        memmove(bus->wqueue, bus->wqueue + 1, sizeof(sd_bus_message*) * bus->wqueue_size);
                        bus->windex = 0;

                        c++;
                }
        }

        return c;
}

static int dispatch_rqueue(sd_bus *bus, sd_bus_message **m) {
        int r;

        assert(bus);
        assert(m);

        if (bus->fd < 0)
                return -ENOTCONN;

        if (bus->rqueue_size > 0) {
                /* Dispatch a queued message */

                *m = bus->rqueue[0];
                bus->rqueue_size --;
                memmove(bus->rqueue, bus->rqueue + 1, sizeof(sd_bus_message*) * bus->rqueue_size);
                return 1;
        }

        /* Try to read a new message */
        r = message_read(bus, m);
        if (r < 0) {
                sd_bus_close(bus);
                return r;
        }

        return r;
}

int sd_bus_send(sd_bus *bus, sd_bus_message *m, uint64_t *serial) {
        int r;

        if (!bus)
                return -EINVAL;
        if (bus->fd < 0)
                return -ENOTCONN;
        if (!m)
                return -EINVAL;
        if (m->header->version > bus->message_version)
                return -EPERM;

        r = bus_seal_message(bus, m);
        if (r < 0)
                return r;

        if (bus->wqueue_size <= 0) {
                size_t idx = 0;

                r = message_write(bus, m, &idx);
                if (r < 0) {
                        sd_bus_close(bus);
                        return r;
                } else if (r == 0)  {
                        /* Wasn't fully written. So let's remember how
                         * much was written. Note that the first entry
                         * of the wqueue array is always allocated so
                         * that we always can remember how much was
                         * written. */
                        bus->wqueue[0] = sd_bus_message_ref(m);
                        bus->wqueue_size = 1;
                        bus->windex = idx;
                }
        } else {
                sd_bus_message **q;

                /* Just append it to the queue. */

                if (bus->wqueue_size >= WQUEUE_MAX)
                        return -ENOBUFS;

                q = realloc(bus->wqueue, sizeof(sd_bus_message*) * (bus->wqueue_size + 1));
                if (!q)
                        return -ENOMEM;

                bus->wqueue = q;
                q[bus->wqueue_size ++] = sd_bus_message_ref(m);
        }

        if (serial)
                *serial = BUS_MESSAGE_SERIAL(m);

        return 0;
}

static usec_t calc_elapse(uint64_t usec) {
        if (usec == (uint64_t) -1)
                return 0;

        if (usec == 0)
                usec = SD_BUS_DEFAULT_TIMEOUT;

        return now(CLOCK_MONOTONIC) + usec;
}

int sd_bus_send_with_reply(
                sd_bus *bus,
                sd_bus_message *m,
                sd_message_handler_t callback,
                void *userdata,
                uint64_t usec,
                uint64_t *serial) {

        struct reply_callback *c;
        int r;

        if (!bus)
                return -EINVAL;
        if (!bus->fd < 0)
                return -ENOTCONN;
        if (!m)
                return -EINVAL;
        if (!callback)
                return -EINVAL;
        if (!m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return -EINVAL;

        r = bus_seal_message(bus, m);
        if (r < 0)
                return r;

        c = new(struct reply_callback, 1);
        if (!c)
                return -ENOMEM;

        c->callback = callback;
        c->userdata = userdata;
        c->serial = BUS_MESSAGE_SERIAL(m);
        c->timeout = calc_elapse(usec);

        r = hashmap_put(bus->reply_callbacks, &c->serial, c);
        if (r < 0) {
                free(c);
                return r;
        }

        r = sd_bus_send(bus, m, serial);
        if (r < 0) {
                hashmap_remove(bus->reply_callbacks, &c->serial);
                free(c);
                return r;
        }

        return r;
}

int sd_bus_send_with_reply_cancel(sd_bus *bus, uint64_t serial) {
        struct reply_callbacks *c;

        if (!bus)
                return -EINVAL;
        if (serial == 0)
                return -EINVAL;

        c = hashmap_remove(bus->reply_callbacks, &serial);
        if (!c)
                return 0;

        free(c);
        return 1;
}

int sd_bus_send_with_reply_and_block(
                sd_bus *bus,
                sd_bus_message *m,
                uint64_t usec,
                sd_bus_error *error,
                sd_bus_message **reply) {

        int r;
        usec_t timeout;
        uint64_t serial;
        bool room = false;

        if (!bus)
                return -EINVAL;
        if (!bus->fd < 0)
                return -ENOTCONN;
        if (!m)
                return -EINVAL;
        if (!m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return -EINVAL;
        if (sd_bus_error_is_set(error))
                return -EINVAL;

        r = sd_bus_send(bus, m, &serial);
        if (r < 0)
                return r;

        timeout = calc_elapse(usec);

        for (;;) {
                usec_t left;
                sd_bus_message *incoming;

                if (!room) {
                        sd_bus_message **q;

                        /* Make sure there's room for queuing this
                         * locally, before we read the message */

                        q = realloc(bus->rqueue, (bus->rqueue_size + 1) * sizeof(sd_bus_message*));
                        if (!q)
                                return -ENOMEM;

                        bus->rqueue = q;
                        room = true;
                }

                r = message_read(bus, &incoming);
                if (r < 0)
                        return r;
                if (r > 0) {
                        if (incoming->reply_serial == serial) {
                                /* Found a match! */

                                if (incoming->header->type == SD_BUS_MESSAGE_TYPE_METHOD_RETURN) {
                                        *reply = incoming;
                                        return 0;
                                }

                                if (incoming->header->type == SD_BUS_MESSAGE_TYPE_METHOD_ERROR) {
                                        int k;

                                        r = sd_bus_error_copy(error, &incoming->error);
                                        if (r < 0) {
                                                sd_bus_message_unref(incoming);
                                                return r;
                                        }

                                        k = bus_error_to_errno(&incoming->error);
                                        sd_bus_message_unref(incoming);
                                        return k;
                                }

                                sd_bus_message_unref(incoming);
                                return -EIO;
                        }

                        /* There's already guaranteed to be room for
                         * this, so need to resize things here */
                        bus->rqueue[bus->rqueue_size ++] = incoming;
                        room = false;

                        /* Try to read more, right-away */
                        continue;
                }

                if (timeout > 0) {
                        usec_t n;

                        n = now(CLOCK_MONOTONIC);
                        if (n >= timeout)
                                return -ETIMEDOUT;

                        left = timeout - n;
                } else
                        left = (uint64_t) -1;

                r = sd_bus_wait(bus, left);
                if (r < 0)
                        return r;

                r = dispatch_wqueue(bus);
                if (r < 0)
                        return r;
        }
}

int sd_bus_get_fd(sd_bus *bus) {
        if (!bus)
                return -EINVAL;

        if (bus->fd < 0)
                return -EINVAL;

        return bus->fd;
}

int sd_bus_get_events(sd_bus *bus) {
        int flags = 0;

        if (!bus)
                return -EINVAL;

        if (bus->fd < 0)
                return -EINVAL;

        if (bus->state == BUS_OPENING)
                flags |= POLLOUT;
        else if (bus->state == BUS_RUNNING || bus->state == BUS_HELLO) {
                if (bus->rqueue_size <= 0)
                        flags |= POLLIN;
                if (bus->wqueue_size > 0)
                        flags |= POLLOUT;
        }

        return flags;
}

int sd_bus_process(sd_bus *bus, sd_bus_message **ret) {
        sd_bus_message *m;
        int r;

        if (!bus)
                return -EINVAL;
        if (bus->fd < 0)
                return -ENOTCONN;

        if (bus->state == BUS_OPENING) {
                struct pollfd p;

                zero(p);
                p.fd = bus->fd;
                p.events = POLLOUT;

                r = poll(&p, 1, 0);
                if (r < 0)
                        return -errno;

                if (p.revents & (POLLOUT|POLLERR|POLLHUP)) {
                        int error;
                        socklen_t slen = sizeof(error);

                        r = getsockopt(bus->fd, SOL_SOCKET, SO_ERROR, &error, &slen);
                        if (r < 0)
                                return -errno;

                        if (error != 0)
                                bus->last_connect_error = -error;
                        else if (p.revents & (POLLERR|POLLHUP))
                                bus->last_connect_error = -ECONNREFUSED;
                        else
                                return bus_start_auth(bus);

                        /* Try next address */
                        return bus_start_connect(bus);
                }

                return 0;

        } else if (bus->state == BUS_AUTHENTICATING) {

                r = bus_write_auth(bus);
                if (r < 0)
                        return r;

                r = bus_read_auth(bus);
                if (r <= 0)
                        return r;

                return bus_start_running(bus);

        } else if (bus->state == BUS_RUNNING || bus->state == BUS_HELLO) {
                struct filter_callback *l;

                r = dispatch_wqueue(bus);
                if (r < 0)
                        return r;

                r = dispatch_rqueue(bus, &m);
                if (r <= 0)
                        return r;

                if (m->header->type == SD_BUS_MESSAGE_TYPE_METHOD_CALL || m->header->type == SD_BUS_MESSAGE_TYPE_METHOD_RETURN) {
                        struct reply_callback *c;

                        c = hashmap_remove(bus->reply_callbacks, &m->reply_serial);
                        if (c) {
                                r = c->callback(bus, m, c->userdata);
                                free(c);

                                if (r != 0) {
                                        sd_bus_message_unref(m);
                                        return r < 0 ? r : 0;
                                }
                        }
                }

                LIST_FOREACH(callbacks, l, bus->filter_callbacks) {
                        r = l->callback(bus, m, l->userdata);
                        if (r != 0) {
                                sd_bus_message_unref(m);
                                return r < 0 ? r : 0;
                        }
                }

                if (ret) {
                        *ret = m;
                        return 1;
                }

                sd_bus_message_unref(m);
                return 0;
        }

        return -ENOTSUP;
}

int sd_bus_wait(sd_bus *bus, uint64_t timeout_usec) {
        struct pollfd p;
        int r, e;
        struct timespec ts;

        if (!bus)
                return -EINVAL;
        if (bus->fd < 0)
                return -ECONNREFUSED;

        e = sd_bus_get_events(bus);
        if (e < 0)
                return e;

        zero(p);
        p.fd = bus->fd;
        p.events = e;

        r = ppoll(&p, 1, timeout_usec == (uint64_t) -1 ? NULL : timespec_store(&ts, timeout_usec), NULL);
        if (r < 0)
                return -EINVAL;

        return r;
}

int sd_bus_flush(sd_bus *bus) {
        int r;

        if (!bus)
                return -EINVAL;
        if (bus->fd < 0)
                return -ENOTCONN;

        if (bus->state == BUS_RUNNING && bus->wqueue_size <= 0)
                return 0;

        for (;;) {
                r = dispatch_wqueue(bus);
                if (r < 0)
                        return r;

                if (bus->state == BUS_RUNNING && bus->wqueue_size <= 0)
                        return 0;

                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0)
                        return r;
        }
}

int sd_bus_add_filter(sd_bus *bus, sd_message_handler_t callback, void *userdata) {
        struct filter_callback *f;

        if (!bus)
                return -EINVAL;
        if (!callback)
                return -EINVAL;

        f = new(struct filter_callback, 1);
        if (!f)
                return -ENOMEM;
        f->callback = callback;
        f->userdata = userdata;

        LIST_PREPEND(struct filter_callback, callbacks, bus->filter_callbacks, f);
        return 0;
}

int sd_bus_remove_filter(sd_bus *bus, sd_message_handler_t callback, void *userdata) {
        struct filter_callback *f;

        if (!bus)
                return -EINVAL;
        if (!callback)
                return -EINVAL;

        LIST_FOREACH(callbacks, f, bus->filter_callbacks) {
                if (f->callback == callback && f->userdata == userdata) {
                        LIST_REMOVE(struct filter_callback, callbacks, bus->filter_callbacks, f);
                        free(f);
                        return 1;
                }
        }

        return 0;
}
