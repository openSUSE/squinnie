#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# security scanner - scan a system's security related information
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

import os

class DumpIO(object):
    """This class manages saving and loading whole dumps and parts to and from the filesystem."""

    def __init__(self, target, path="/tmp/security-scanner"):
        """
        :param target: The name of target scanned (for naming the storage folders).
        :param path: The path to use for the dump data.
        """

        self.m_target_name = target
        self.m_path_prefix = path

    def _getDumpFolder(self):
        """
        Generates the path of the dump folder.
        :return: The path of the dump folder without trailing slash.
        """
        return os.path.join(self.m_path_prefix, self.m_target_name)

    def saveFullDump(self, data):
        """
        Saves all dump data to the specified directory.
        :param data: The dumped data.
        """
        pass
