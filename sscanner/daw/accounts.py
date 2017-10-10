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
from sscanner.daw.helper import LazyLoader


class AccountWrapper(object):
    """
    This class abstracts all data about users and groups. So far this data is unfortunately only the mapping of the
    uid/gid to a name, which does not allow any more metadata (for example home directories).
    """

    def __init__(self, dumpIO):
        """
        :param dumpIO: An instance of sscanner.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_data = {}
        self.m_ll_data = LazyLoader("userdata", self.m_dumpIO)

    def getNameForUid(self, uid, default=None):
        """Returns the name of the user for a specific uid."""
        data = self.m_ll_data.getData()['uids']
        return data[uid] if uid in data else default

    def getNameForGid(self, gid, default=None):
        """Returns the name of the group for a specific group id."""
        data = self.m_ll_data.getData()['gids']
        return data[gid] if gid in data else default
