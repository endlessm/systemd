# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2018 Endless Mobile, Inc
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

systemd_readahead_sources = files('''
        readahead.c
        readahead-collect.c
        readahead-replay.c
        readahead-analyze.c
        readahead-common.c
        readahead-common.h
'''.split())

tests += [
        [['src/readahead/test-ssd.c',
          'src/readahead/readahead-common.c',
          'src/readahead/readahead-common.h'],
         [],
         [],
         'ENABLE_READAHEAD', 'manual'],
]
