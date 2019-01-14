#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author: Sebastian Kaim
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301 USA.
from sscanner.daw.helper import CategoryLoader


class AccountWrapper(object):
    """
    This class abstracts all data about users and groups. So far this data is unfortunately only the mapping of the
    uid/gid to a name, which does not allow any more metadata (for example home directories).
    """

    def __init__(self, dumpIO, uid_gid=None):
        """
        :param dumpIO: An instance of sscanner.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_ll_data = CategoryLoader("userdata", self.m_dumpIO)
        self.m_data = self.m_ll_data.getData()
        if uid_gid:
            for ns in uid_gid.items():
                if not ns[1]['uid'] and not ns[1]['gid']:
                    # empty set
                    continue
                uid_offset = int(ns[1]['uid'][0][1])
                gid_offset = int(ns[1]['gid'][0][1])
                for ids in [(uid_offset, 'uids'), (gid_offset, 'gids')]:
                    for mapping in ns[1][ids[1]].items():
                        value = int(mapping[0]) + ids[0]
                        if not value in self.m_data[ids[1]]:
                            self.m_data[ids[1]][value] = "{}(user-ns)".format(
                                    mapping[1]
                            )
                        else:
                            error = """Overlapping {}: {} already exists!
                            This could be caused by misconfigured
                            uid/gid mapping on scanning target!""".format(
                                ids[1], value
                            )
                            raise ValueError(error)

    def getNameForUid(self, uid, default=None):
        """Returns the name of the user for a specific uid."""
        data = self.m_data['uids']
        return data[int(uid)] if int(uid) in data else default

    def getNameForGid(self, gid, default=None):
        """Returns the name of the group for a specific group id."""
        data = self.m_data['gids']
        return data[int(gid)] if int(gid) in data else default

    def getGidForName(self, name):
        """Returns the GID for an account or None if it can't be resolved."""
        # this lookup is quite inefficient, but so far its only used once per execution and one shouldn't over-optimize.
        data = self.m_data['gids']
        for gid, gname in data.items():
            if gname == name:
                return gid
        return None

    def getUidForName(self, name):
        """Returns the GID for an account or None if it can't be resolved."""
        # this lookup is quite inefficient, but so far its only used once per execution and one shouldn't over-optimize.
        data = self.m_data['uids']
        for uid, uname in data.items():
            if uname == name:
                return uid
        return None
