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

#include <fcntl.h>
#include <sys/mman.h>

#include "journal-def.h"
#include "journal-file.h"
#include "journal-authenticate.h"
#include "fsprg.h"

static void *fsprg_state(JournalFile *f) {
        uint64_t a, b;
        assert(f);

        if (!f->authenticate)
                return NULL;

        a = le64toh(f->fsprg_header->header_size);
        b = le64toh(f->fsprg_header->state_size);

        if (a + b > f->fsprg_size)
                return NULL;

        return (uint8_t*) f->fsprg_header + a;
}

static uint64_t journal_file_tag_seqnum(JournalFile *f) {
        uint64_t r;

        assert(f);

        r = le64toh(f->header->n_tags) + 1;
        f->header->n_tags = htole64(r);

        return r;
}

int journal_file_append_tag(JournalFile *f) {
        Object *o;
        uint64_t p;
        int r;

        assert(f);

        if (!f->authenticate)
                return 0;

        if (!f->hmac_running)
                return 0;

        log_debug("Writing tag for epoch %llu\n", (unsigned long long) FSPRG_GetEpoch(fsprg_state(f)));

        assert(f->hmac);

        r = journal_file_append_object(f, OBJECT_TAG, sizeof(struct TagObject), &o, &p);
        if (r < 0)
                return r;

        o->tag.seqnum = htole64(journal_file_tag_seqnum(f));

        /* Add the tag object itself, so that we can protect its
         * header. This will exclude the actual hash value in it */
        r = journal_file_hmac_put_object(f, OBJECT_TAG, p);
        if (r < 0)
                return r;

        /* Get the HMAC tag and store it in the object */
        memcpy(o->tag.tag, gcry_md_read(f->hmac, 0), TAG_LENGTH);
        f->hmac_running = false;

        return 0;
}

static int journal_file_hmac_start(JournalFile *f) {
        uint8_t key[256 / 8]; /* Let's pass 256 bit from FSPRG to HMAC */

        assert(f);

        if (!f->authenticate)
                return 0;

        if (f->hmac_running)
                return 0;

        /* Prepare HMAC for next cycle */
        gcry_md_reset(f->hmac);
        FSPRG_GetKey(fsprg_state(f), key, sizeof(key), 0);
        gcry_md_setkey(f->hmac, key, sizeof(key));

        f->hmac_running = true;

        return 0;
}

static int journal_file_get_epoch(JournalFile *f, uint64_t realtime, uint64_t *epoch) {
        uint64_t t;

        assert(f);
        assert(epoch);
        assert(f->authenticate);

        if (le64toh(f->fsprg_header->fsprg_start_usec) == 0 ||
            le64toh(f->fsprg_header->fsprg_interval_usec) == 0)
                return -ENOTSUP;

        if (realtime < le64toh(f->fsprg_header->fsprg_start_usec))
                return -ESTALE;

        t = realtime - le64toh(f->fsprg_header->fsprg_start_usec);
        t = t / le64toh(f->fsprg_header->fsprg_interval_usec);

        *epoch = t;
        return 0;
}

static int journal_file_need_evolve(JournalFile *f, uint64_t realtime) {
        uint64_t goal, epoch;
        int r;
        assert(f);

        if (!f->authenticate)
                return 0;

        r = journal_file_get_epoch(f, realtime, &goal);
        if (r < 0)
                return r;

        epoch = FSPRG_GetEpoch(fsprg_state(f));
        if (epoch > goal)
                return -ESTALE;

        return epoch != goal;
}

static int journal_file_evolve(JournalFile *f, uint64_t realtime) {
        uint64_t goal, epoch;
        int r;

        assert(f);

        if (!f->authenticate)
                return 0;

        r = journal_file_get_epoch(f, realtime, &goal);
        if (r < 0)
                return r;

        epoch = FSPRG_GetEpoch(fsprg_state(f));
        if (epoch < goal)
                log_debug("Evolving FSPRG key from epoch %llu to %llu.", (unsigned long long) epoch, (unsigned long long) goal);

        for (;;) {
                if (epoch > goal)
                        return -ESTALE;
                if (epoch == goal)
                        return 0;

                FSPRG_Evolve(fsprg_state(f));
                epoch = FSPRG_GetEpoch(fsprg_state(f));
        }
}

int journal_file_maybe_append_tag(JournalFile *f, uint64_t realtime) {
        int r;

        assert(f);

        if (!f->authenticate)
                return 0;

        r = journal_file_need_evolve(f, realtime);
        if (r <= 0)
                return 0;

        r = journal_file_append_tag(f);
        if (r < 0)
                return r;

        r = journal_file_evolve(f, realtime);
        if (r < 0)
                return r;

        r = journal_file_hmac_start(f);
        if (r < 0)
                return r;

        return 0;
}

int journal_file_hmac_put_object(JournalFile *f, int type, uint64_t p) {
        int r;
        Object *o;

        assert(f);

        if (!f->authenticate)
                return 0;

        r = journal_file_hmac_start(f);
        if (r < 0)
                return r;

        r = journal_file_move_to_object(f, type, p, &o);
        if (r < 0)
                return r;

        gcry_md_write(f->hmac, o, offsetof(ObjectHeader, payload));

        switch (o->object.type) {

        case OBJECT_DATA:
                /* All but: hash and payload are mutable */
                gcry_md_write(f->hmac, &o->data.hash, sizeof(o->data.hash));
                gcry_md_write(f->hmac, o->data.payload, le64toh(o->object.size) - offsetof(DataObject, payload));
                break;

        case OBJECT_ENTRY:
                /* All */
                gcry_md_write(f->hmac, &o->entry.seqnum, le64toh(o->object.size) - offsetof(EntryObject, seqnum));
                break;

        case OBJECT_FIELD_HASH_TABLE:
        case OBJECT_DATA_HASH_TABLE:
        case OBJECT_ENTRY_ARRAY:
                /* Nothing: everything is mutable */
                break;

        case OBJECT_TAG:
                /* All but the tag itself */
                gcry_md_write(f->hmac, &o->tag.seqnum, sizeof(o->tag.seqnum));
                break;
        default:
                return -EINVAL;
        }

        return 0;
}

int journal_file_hmac_put_header(JournalFile *f) {
        int r;

        assert(f);

        if (!f->authenticate)
                return 0;

        r = journal_file_hmac_start(f);
        if (r < 0)
                return r;

        /* All but state+reserved, boot_id, arena_size,
         * tail_object_offset, n_objects, n_entries, tail_seqnum,
         * head_entry_realtime, tail_entry_realtime,
         * tail_entry_monotonic, n_data, n_fields, header_tag */

        gcry_md_write(f->hmac, f->header->signature, offsetof(Header, state) - offsetof(Header, signature));
        gcry_md_write(f->hmac, &f->header->file_id, offsetof(Header, boot_id) - offsetof(Header, file_id));
        gcry_md_write(f->hmac, &f->header->seqnum_id, offsetof(Header, arena_size) - offsetof(Header, seqnum_id));
        gcry_md_write(f->hmac, &f->header->data_hash_table_offset, offsetof(Header, tail_object_offset) - offsetof(Header, data_hash_table_offset));
        gcry_md_write(f->hmac, &f->header->head_entry_seqnum, offsetof(Header, head_entry_realtime) - offsetof(Header, head_entry_seqnum));

        return 0;
}

int journal_file_load_fsprg(JournalFile *f) {
        int r, fd = -1;
        char *p = NULL;
        struct stat st;
        FSPRGHeader *m = NULL;
        sd_id128_t machine;

        assert(f);

        if (!f->authenticate)
                return 0;

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return r;

        if (asprintf(&p, "/var/log/journal/" SD_ID128_FORMAT_STR "/fsprg",
                     SD_ID128_FORMAT_VAL(machine)) < 0)
                return -ENOMEM;

        fd = open(p, O_RDWR|O_CLOEXEC|O_NOCTTY, 0600);
        if (fd < 0) {
                log_error("Failed to open %s: %m", p);
                r = -errno;
                goto finish;
        }

        if (fstat(fd, &st) < 0) {
                r = -errno;
                goto finish;
        }

        if (st.st_size < (off_t) sizeof(FSPRGHeader)) {
                r = -ENODATA;
                goto finish;
        }

        m = mmap(NULL, PAGE_ALIGN(sizeof(FSPRGHeader)), PROT_READ, MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) {
                m = NULL;
                r = -errno;
                goto finish;
        }

        if (memcmp(m->signature, FSPRG_HEADER_SIGNATURE, 8) != 0) {
                r = -EBADMSG;
                goto finish;
        }

        if (m->incompatible_flags != 0) {
                r = -EPROTONOSUPPORT;
                goto finish;
        }

        if (le64toh(m->header_size) < sizeof(FSPRGHeader)) {
                r = -EBADMSG;
                goto finish;
        }

        if (le64toh(m->state_size) != FSPRG_stateinbytes(m->secpar)) {
                r = -EBADMSG;
                goto finish;
        }

        f->fsprg_size = le64toh(m->header_size) + le64toh(m->state_size);
        if ((uint64_t) st.st_size < f->fsprg_size) {
                r = -ENODATA;
                goto finish;
        }

        if (!sd_id128_equal(machine, m->machine_id)) {
                r = -EHOSTDOWN;
                goto finish;
        }

        if (le64toh(m->fsprg_start_usec) <= 0 ||
            le64toh(m->fsprg_interval_usec) <= 0) {
                r = -EBADMSG;
                goto finish;
        }

        f->fsprg_header = mmap(NULL, PAGE_ALIGN(f->fsprg_size), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (f->fsprg_header == MAP_FAILED) {
                f->fsprg_header = NULL;
                r = -errno;
                goto finish;
        }

        r = 0;

finish:
        if (m)
                munmap(m, PAGE_ALIGN(sizeof(FSPRGHeader)));

        if (fd >= 0)
                close_nointr_nofail(fd);

        free(p);
        return r;
}

int journal_file_setup_hmac(JournalFile *f) {
        gcry_error_t e;

        if (!f->authenticate)
                return 0;

        e = gcry_md_open(&f->hmac, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
        if (e != 0)
                return -ENOTSUP;

        return 0;
}

int journal_file_append_first_tag(JournalFile *f) {
        int r;
        uint64_t p;

        if (!f->authenticate)
                return 0;

        log_debug("Calculating first tag...");

        r = journal_file_hmac_put_header(f);
        if (r < 0)
                return r;

        p = le64toh(f->header->field_hash_table_offset);
        if (p < offsetof(Object, hash_table.items))
                return -EINVAL;
        p -= offsetof(Object, hash_table.items);

        r = journal_file_hmac_put_object(f, OBJECT_FIELD_HASH_TABLE, p);
        if (r < 0)
                return r;

        p = le64toh(f->header->data_hash_table_offset);
        if (p < offsetof(Object, hash_table.items))
                return -EINVAL;
        p -= offsetof(Object, hash_table.items);

        r = journal_file_hmac_put_object(f, OBJECT_DATA_HASH_TABLE, p);
        if (r < 0)
                return r;

        r = journal_file_append_tag(f);
        if (r < 0)
                return r;

        return 0;
}
