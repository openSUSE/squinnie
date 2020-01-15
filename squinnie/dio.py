#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Squinnie - scan a system's security related information

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
import threading
import shutil
from squinnie import helper
from squinnie.daw.fs import FsDatabase
import logging


class DumpIO(object):
    """This class manages saving and loading whole dumps and parts to
    and from the filesystem.
    """

    FILE_EXTENSION = ".p.gz"
    LOCK_FILE_NAME = '.squinnie.data'

    def __init__(self, target, path="/tmp/squinnie"):
        """
        :param target: The name of target scanned (for naming the storage folders).
        :param path: The path to use for the dump data.
        """
        self.m_target_name = target
        self.m_path_prefix = path
        self.cache = {}

    def getDumpDir(self):
        """
        Generates the path of the dump folder.
        :return: The path of the dump folder without trailing slash.
        """
        return os.path.join(self.m_path_prefix, helper.makeValidDirname(self.m_target_name))

    def _createDumpDirIfItDoesNotExist(self):
        """Creates the dump directory if it does not exist"""
        ddir = self.getDumpDir()

        if not os.path.exists(ddir):
            os.makedirs(ddir)

    def saveFullDump(self, data):
        """
        Saves all dump data to the specified directory.
        :param data: The dumped data.
        """
        self._createDumpDirIfItDoesNotExist()

        # the filesystem needs to be handled in a special way as it's a database instead of a regular dump
        if 'filesystem' in data:
            self.writeOutFilesystem(data.pop('filesystem'))

        for category in data:
            self.writeCategory(category, data[category])

    def writeOutFilesystem(self, data):
        """
        This helper writes out the filesystem database.
        :param data: The fs data.
        """
        logging.debug("Inserting data into fs")
        fsdb = FsDatabase(self.getDumpDir())
        fsdb.insertRawData(data)
        fsdb.close()

    def writeCategory(self, category, data):
        """This method writes a dump category to a file."""
        file_basename = helper.makeValidDirname(category)
        if file_basename != category:
            logging.warning("Category %s has an invalid name, it will be written as %s instead."
                          .format(category, file_basename))

        self._createDumpDirIfItDoesNotExist()
        file = os.path.join(self.getDumpDir(), file_basename + self.FILE_EXTENSION)
        logging.debug("Saving data to {}".format(file))

        # create the lockfile
        open(os.path.join(self.getDumpDir(), self.LOCK_FILE_NAME), 'a').close()

        helper.writePickle(data, file)
        self.cache[category] = data
        # self._debugPrint(data[category])

    def loadFullDump(self):
        """
        This method loads a full dump from the hard disk. This method is
        only for legacy code support and should not be used for any other purpose.
        :return: The raw dump data.
        """
        data = {}
        threads = []

        def fetcher(category):
            data[category] = self.loadCategory(category)

        for c in self.getAllCachedCategories():
            t = threading.Thread(target=fetcher, args=[c])
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        return data

    def loadCategory(self, category):
        """This method loads a specific category file from a dump."""
        if category in self.cache:
            return self.cache[category]

        file_basename = helper.makeValidDirname(category)

        file = os.path.join(self.getDumpDir(), file_basename + self.FILE_EXTENSION)

        if not os.path.exists(file):
            raise LookupError("File '%s' to load category '%s' does not exist!" % (file, category))

        logging.debug("Loading data from {}".format(file))
        self.cache[category] = helper.readPickle(file)
        return self.cache[category]

    def getAllCachedCategories(self):
        """Returns a list of all categories saved on disk"""
        path = self.getDumpDir()

        if not os.path.isdir(path):
            return {}

        return [f.replace(self.FILE_EXTENSION, '')
                for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)) and f.endswith(self.FILE_EXTENSION)]

    def hasCache(self):
        return len(self.getAllCachedCategories()) > 0

    def clearCache(self):
        self.cache.clear()

        path = self.getDumpDir()

        logging.info("Removing cached data in %s!" % path)

        lockfile = os.path.join(path, self.LOCK_FILE_NAME)
        if not os.path.isfile(lockfile):
            logging.error("Refusing to remove %s as there is no lockfile! If you're sure you want to delete this "
                          % path)
            logging.error("If you're sure you want to delete this directory please execute `touch '%s'` and retry."
                          % lockfile)
            exit(2)

        shutil.rmtree(path)

    @staticmethod
    def _debugPrint(data, indent=2, depth=2):
        """
        Pretty-prints the given data to stdout.
        :param data: The data to print.
        """
        pp = pprint.PrettyPrinter(indent=indent, depth=depth)
        pp.pprint(data)
