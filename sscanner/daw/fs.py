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
from helper import LazyLoader
import sqlite3
import os.path
import sscanner.dio


class Filesystem(object):
    """This class abstracts the filesystem data."""

    def __init__(self, dumpIO):
        """
        :param dumpIO: An instance of sscanner.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_data_accessor = LazyLoader(category="filesystem", dumpIO=self.m_dumpIO)

    def getAllFsData(self):
        """Returns all raw filesystem data."""
        # TODO: move FS data refining here
        return self.m_data_accessor.getData()


class FsDatabase(object):
    """This class manages the filesystem database"""
    DB_NAME = 'filesystem.db'

    def __init__(self, path):
        self.m_path = path
        self.m_db = sqlite3.connect(self.getDbPath())

    def getDbPath(self):
        """Returns the path of the database."""
        return os.path.join(self.m_path, self.DB_NAME)

    def createTable(self):
        """Creates the database table, dropping it beforehand if it exists."""
        sql = """
        CREATE TABLE "inodes" (
            "id" INTEGER PRIMARY KEY AUTOINCREMENT,
            "parent" INTEGER,
            "uid" INTEGER,
            "gid" INTEGER,
            "caps" INTEGER,
            "mode" INTEGER,
            "type" TEXT,
            "name" TEXT,
            "path" TEXT
        )
        """

        self.m_db.execute('DROP TABLE IF EXISTS "inodes"')
        self.m_db.execute(sql)

    def insertRawData(self, fsdata):
        """Inserts the raw data into a new database."""
        self.createTable()

        sql = """
        INSERT INTO inodes (parent, uid, gid, caps, mode, name)
        VALUES (?, ?, ?. ?, ?, ?)"""

        keys = sorted(fsdata.keys())
        # cursor =
        pass

    def close(self):
        self.m_db.close()

