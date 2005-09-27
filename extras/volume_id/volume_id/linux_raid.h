/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#ifndef _VOLUME_ID_LINUX_RAID_
#define _VOLUME_ID_LINUX_RAID_

extern int volume_id_probe_linux_raid(struct volume_id *id, uint64_t off, uint64_t size);

#endif
