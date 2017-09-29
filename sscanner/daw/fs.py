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
        self.m_accessor = FsDatabase(self.m_dumpIO.getDumpDir())

    def getAllFsData(self):
        """Returns all raw filesystem data."""
        # TODO: move FS data refining here
        return self.m_accessor.getFullDump()


class FsDatabase(object):
    """This class manages the filesystem database"""
    DB_NAME = 'filesystem.db'

    def __init__(self, path):
        self.m_path = path
        self.m_db = sqlite3.connect(self.getDbPath())
        self.m_db.text_factory = str  # to fix string handling in python2

    def getDbPath(self):
        """Returns the path of the database."""
        return os.path.join(self.m_path, self.DB_NAME)

    def getFullDump(self):
        # TODO
        pass

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

        # sscanner.dio.DumpIO._debugPrint(fsdata, depth=6)
        cursor = self.m_db.cursor()
        self._processDirectory('/', '/', fsdata, 1, cursor)
        self.m_db.commit()

    def _processDirectory(self, name, path, data, parentId, cursor):
        """Inserts a directory from the raw dump in the db."""
        dirSqlData = self._createDataArrayFromProperties(data['properties'], name, path, parentId)
        cursor.execute(self._getInsertSql(), dirSqlData)
        dirId = cursor.lastrowid
        dirPath = os.path.join(path, name)

        fileData = []

        for name, item in data['subitems'].iteritems():
            if item['properties']['type'] == 'd':
                self._processDirectory(name, dirPath, item, dirId, cursor)
            else:
                fileData.append(self._createDataArrayFromProperties(item['properties'], name, dirPath, dirId))

        cursor.executemany(self._getInsertSql(), tuple(fileData))

    @staticmethod
    def _createDataArrayFromProperties(props, name, path, parent):
        """Creates an array to use with insert from a properties dict as delivered by the probe and additional info."""
        return parent, props['st_uid'], props['st_gid'], props['caps'], props['st_mode'], props['type'], name, path

    @staticmethod
    def _getInsertSql():
        """Returns the SQL statement for inserting into the db."""
        return "INSERT INTO inodes (parent, uid, gid, caps, mode, type, name, path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"

    def close(self):
        self.m_db.close()

