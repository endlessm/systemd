#  -*- Mode: python; coding: utf-8; indent-tabs-mode: nil -*- */
#
#  This file is part of systemd.
#
#  Copyright 2012-2013 Zbigniew Jędrzejewski-Szmek
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

import sys
import collections
import xml.etree.ElementTree as tree
import re

TEMPLATE = '''\
<refentry id="systemd.directives" conditional="HAVE_PYTHON">

        <refentryinfo>
                <title>systemd.directives</title>
                <productname>systemd</productname>

                <authorgroup>
                        <author>
                                <contrib>Developer</contrib>
                                <firstname>Zbigniew</firstname>
                                <surname>Jędrzejewski-Szmek</surname>
                                <email>zbyszek@in.waw.pl</email>
                        </author>
                </authorgroup>
        </refentryinfo>

        <refmeta>
                <refentrytitle>systemd.directives</refentrytitle>
                <manvolnum>7</manvolnum>
        </refmeta>

        <refnamediv>
                <refname>systemd.directives</refname>
                <refpurpose>Index of configuration directives</refpurpose>
        </refnamediv>

        <refsect1>
                <title>Unit directives</title>

                <para>Directives for configuring units, used in unit
                files.</para>

                <variablelist id='unit-directives' />
        </refsect1>

        <refsect1>
                <title>Options on the kernel command line</title>

                <para>Kernel boot options for configuring the behaviour of the
                systemd process.</para>

                <variablelist id='kernel-commandline-options' />
        </refsect1>

        <refsect1>
                <title>Environment variables</title>

                <para>Environment variables understood by the systemd
                manager and other programs.</para>

                <variablelist id='environment-variables' />
        </refsect1>

        <refsect1>
                <title>UDEV directives</title>

                <para>Directives for configuring systemd units through the
                udev database.</para>

                <variablelist id='udev-directives' />
        </refsect1>

        <refsect1>
                <title>Journal fields</title>

                <para>Fields in the journal events with a well known meaning.</para>

                <variablelist id='journal-directives' />
        </refsect1>

        <refsect1>
                <title>PAM configuration directives</title>

                <para>Directives for configuring PAM behaviour.</para>

                <variablelist id='pam-directives' />
        </refsect1>

        <refsect1>
                <title>crypttab options</title>

                <para>Options which influence mounted filesystems and
                encrypted volumes.</para>

                <variablelist id='crypttab-options' />
        </refsect1>

        <refsect1>
                <title>System manager directives</title>

                <para>Directives for configuring the behaviour of the
                systemd process.</para>

                <variablelist id='systemd-directives' />
        </refsect1>

        <refsect1>
                <title>bootchart.conf directives</title>

                <para>Directives for configuring the behaviour of the
                systemd-bootchart process.</para>

                <variablelist id='bootchart-directives' />
        </refsect1>

        <refsect1>
                <title>command-line options</title>

                <para>Command-line options accepted by programs in the
                systemd suite.</para>

                <variablelist id='options' />
        </refsect1>

        <refsect1>
                <title>Miscellaneous options and directives</title>

                <para>Other configuration elements which don't fit in
                any of the above groups.</para>

                <variablelist id='miscellaneous' />
        </refsect1>

        <refsect1>
                <title>Colophon</title>
                <para id='colophon' />
        </refsect1>
</refentry>
'''

COLOPHON = '''\
This index contains {count} entries in {sections} sections,
referring to {pages} individual manual pages.
'''

def _extract_directives(directive_groups, formatting, page):
    t = tree.parse(page)
    section = t.find('./refmeta/manvolnum').text
    pagename = t.find('./refmeta/refentrytitle').text
    for variablelist in t.iterfind('.//variablelist'):
        klass = variablelist.attrib.get('class')
        storvar = directive_groups[klass or 'miscellaneous']
        storopt = directive_groups['options']
        # <option>s go in OPTIONS, unless class is specified
        for xpath, stor in (('./varlistentry/term/varname', storvar),
                            ('./varlistentry/term/option',
                             storvar if klass else storopt)):
            for name in variablelist.iterfind(xpath):
                text = re.sub(r'([= ]).*', r'\1', name.text).rstrip()
                stor[text].append((pagename, section))
                if text not in formatting:
                    # use element as formatted display
                    name.tail = ''
                    name.text = text
                    formatting[text] = name

def _make_section(template, name, directives, formatting):
    varlist = template.find(".//*[@id='{}']".format(name))
    for varname, manpages in sorted(directives.items()):
        entry = tree.SubElement(varlist, 'varlistentry')
        term = tree.SubElement(entry, 'term')
        term.append(formatting[varname])

        para = tree.SubElement(tree.SubElement(entry, 'listitem'), 'para')

        b = None
        for manpage, manvolume in sorted(set(manpages)):
                if b is not None:
                        b.tail = ', '
                b = tree.SubElement(para, 'citerefentry')
                c = tree.SubElement(b, 'refentrytitle')
                c.text = manpage
                d = tree.SubElement(b, 'manvolnum')
                d.text = manvolume
        entry.tail = '\n\n'

def _make_colophon(template, groups):
    count = 0
    pages = set()
    for group in groups:
        count += len(group)
        for pagelist in group.values():
            pages |= set(pagelist)

    para = template.find(".//para[@id='colophon']")
    para.text = COLOPHON.format(count=count,
                                sections=len(groups),
                                pages=len(pages))

def _make_page(template, directive_groups, formatting):
    """Create an XML tree from directive_groups.

    directive_groups = {
       'class': {'variable': [('manpage', 'manvolume'), ...],
                 'variable2': ...},
       ...
    }
    """
    for name, directives in directive_groups.items():
            _make_section(template, name, directives, formatting)

    _make_colophon(template, directive_groups.values())

    return template

def make_page(*xml_files):
    "Extract directives from xml_files and return XML index tree."
    template = tree.fromstring(TEMPLATE)
    names = [vl.get('id') for vl in template.iterfind('.//variablelist')]
    directive_groups = {name:collections.defaultdict(list)
                        for name in names}
    formatting = {}
    for page in xml_files:
        try:
            _extract_directives(directive_groups, formatting, page)
        except Exception:
            raise ValueError("failed to process " + page)

    return _make_page(template, directive_groups, formatting)

if __name__ == '__main__':
    tree.dump(make_page(*sys.argv[1:]))
