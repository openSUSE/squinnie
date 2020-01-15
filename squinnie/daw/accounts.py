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
from squinnie.daw.helper import CategoryLoader


class AccountWrapper(object):
    """
    This class abstracts all data about users and groups. So far this data is unfortunately only the mapping of the
    uid/gid to a name, which does not allow any more metadata (for example home directories).
    """

    def __init__(self, dumpIO, uid_gid=None):
        """
        :param dumpIO: An instance of squinnie.dio.DumpIO for loading the data
        :dict uid_gid: contains inode: data entries of found user namespaces
        """
        self.m_dumpIO = dumpIO
        self.m_ll_data = CategoryLoader("userdata", self.m_dumpIO)
        self.m_data = self.m_ll_data.getData()
        if uid_gid:
            # load additional uid/gid-mappings from inside user namespaces
            for inode, ns_data in uid_gid.items():
                if not ns_data['uid'] and not ns_data['gid']:
                    # no uid-/gid-mappings inside this user-namespace
                    continue
                # mapping-lists contain the following structure:
                # ID-inside-ns  ID-outside-ns   length
                # however, there can be multiple entries, we only care
                # about the first one and the offset of the parent ids.
                uid_offset = int(ns_data['uid'][0][1])
                gid_offset = int(ns_data['gid'][0][1])
                for offset, key in [
                        (uid_offset, 'uids'), (gid_offset, 'gids')
                ]:
                    for mapping in ns_data[key].items():
                        value = int(mapping[0]) + offset
                        if not value in self.m_data[key]:
                            # adding the ids to the ones we already know
                            self.m_data[key][value] = "{}(user-ns)".format(
                                    mapping[1]
                            )
                        else:
                            error = """Overlapping {}: {} already exists!
                            This could be caused by misconfigured
                            uid/gid mapping on scanning target!""".format(
                                key, value
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
