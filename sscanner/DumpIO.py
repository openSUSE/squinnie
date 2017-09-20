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
import pprint
from sscanner import helper


class DumpIO(object):
    """This class manages saving and loading whole dumps and parts to and from the filesystem."""
    FILE_EXTENSION = ".p.gz"

    def __init__(self, target, path="/tmp/security-scanner"):
        """
        :param target: The name of target scanned (for naming the storage folders).
        :param path: The path to use for the dump data.
        """

        self.m_target_name = target
        self.m_path_prefix = path

    def _getDumpDir(self):
        """
        Generates the path of the dump folder.
        :return: The path of the dump folder without trailing slash.
        """
        return os.path.join(self.m_path_prefix, helper.makeValidDirname(self.m_target_name))

    def _createdDumpDirIfItDoesNotExist(self):
        """Creates the dump directory if it does not exist"""
        ddir = self._getDumpDir()

        if not os.path.exists(ddir):
            os.makedirs(ddir)

    def saveFullDump(self, data):
        """
        Saves all dump data to the specified directory.
        :param data: The dumped data.
        """
        for category in data:
            self.writeCategory(category, data[category])

    def writeCategory(self, category, data):
        file_basename = helper.makeValidDirname(category)
        if file_basename != category:
            helper.eprint("Warning: Category %s has an invalid name, it will be written as %s instead."
                          .format(category, file_basename))

        self._createdDumpDirIfItDoesNotExist()
        file = os.path.join(self._getDumpDir(), file_basename + self.FILE_EXTENSION)
        print("Saving data to {}".format(file))

        helper.writePickle(data, file)
        # self._debugPrint(data[category])

    def loadFullDump(self):
        """
        This method loads a full dump from the hard disk. This method is only for legacy code support and should not be
        used for any other purpose.
        :return: The raw dump data.
        """
        pass

    @staticmethod
    def _debugPrint(data, indent=2, depth=2):
        """
        Pretty-prints the given data to stdout.
        :param data: The data to print.
        """
        pp = pprint.PrettyPrinter(indent=indent, depth=depth)
        pp.pprint(data)
