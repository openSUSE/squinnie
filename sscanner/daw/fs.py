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
import stat
import json
import sscanner.file_mode as file_mode


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

    def queryFilesystem(self, fsquery):
        """Returns the result of a query on the filesystem database with the given parameters."""
        return self.m_accessor.executeFsQuery(fsquery)

    def getFileProperties(self, path):
        """Returns the properties of a specific file on the filesystem."""
        data = self.m_accessor.getFileProperties(os.path.dirname(path), os.path.basename(path))
        return FsDatabase.dbTupleToArray(data)


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
        """Fetches the whole filesystem. Probably not a performant idea."""
        return self.findData()

    def findData(self, where="1=1"):
        """Fetches the data from the filesystem given a where SQL substring. Do note that the given string will not be
        escaped!"""
        cursor = self.m_db.execute("SELECT * FROM inodes WHERE %s" % where)
        return cursor.fetchall()

    def executeFsQuery(self, fsquery):
        """Returns all files matching a given FsQuery instance."""
        sql = "SELECT * FROM inodes %s" % fsquery.getSqlClause()
        cursor = self.m_db.execute(sql)
        return FilesystemIterator(cursor)

    def getFileProperties(self, path, name):
        data = self.m_db.execute('SELECT * FROM inodes WHERE name=? AND path=?', (name, path))
        return data.fetchone()

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

        cursor = self.m_db.cursor()
        self._processDirectory('/', '/', fsdata, 1, cursor)
        self.m_db.commit()

    def _processDirectory(self, name, path, data, parentId, cursor):
        """Inserts a directory from the raw dump in the db."""
        dir_sql_data = self._createDataArrayFromProperties(data['properties'], name, path, parentId)
        cursor.execute(self._getInsertSql(), dir_sql_data)
        dir_id = cursor.lastrowid
        dir_path = os.path.join(path, name)

        file_data = []

        for name, item in data['subitems'].iteritems():
            if item['properties']['type'] == 'd':
                self._processDirectory(name, dir_path, item, dir_id, cursor)
            else:
                file_data.append(self._createDataArrayFromProperties(item['properties'], name, dir_path, dir_id))

        cursor.executemany(self._getInsertSql(), tuple(file_data))

    @staticmethod
    def _createDataArrayFromProperties(props, name, path, parent):
        """Creates a tuple use with insert from a properties dict as delivered by the probe and additional info."""
        mode = props['st_mode']
        return parent, props['st_uid'], props['st_gid'], props['caps'], mode, file_mode.getTypeChar(mode), name, path

    @staticmethod
    def _getInsertSql():
        """Returns the SQL statement for inserting into the db."""
        return "INSERT INTO inodes (parent, uid, gid, caps, mode, type, name, path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"

    def close(self):
        self.m_db.close()

    @staticmethod
    def dbTupleToArray(db_tuple):
        if db_tuple is None:
            return None

        properties = {
            "caps": db_tuple[4],
            "st_mode": db_tuple[5],
            "st_uid": db_tuple[2],
            "st_gid": db_tuple[3],
            "type": db_tuple[6]
        }
        return properties


class FsQuery(object):
    """This class represents a query to the FS database."""

    def __init__(self):
        # this is a list of possible ways to qualify a file for printing
        self.m_or_list = []

        # this is a list of all qualifiers a file needs to match _in addition to_ an item from the or list
        self.m_and_list = []

    def getSqlClause(self):
        """Returns the query as SQL clause (with where)."""
        or_list = "(" + (" OR ".join(self.m_or_list)) + ")"

        and_list = (self.m_and_list + [or_list]) if len(self.m_or_list) > 0 else self.m_and_list
        result = " AND ".join(and_list)

        return "WHERE %s" % result if len(result) > 0 else ""

    def filterForSpecialBits(self):
        """Adds a filter for SUID, SGID or SVTX bits."""
        self.addOrClause('(mode & %s) != 0' % hex(stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX))

    def addAndClause(self, clause):
        """
        Ads a new and clause to the query. WARNING: the string will be inserted into the query unescaped!
        """
        self.m_and_list.append("(%s)" % clause)

    def addOrClause(self, clause):
        """
        Ads a new or clause to the query. WARNING: the string will be inserted into the query unescaped!
        """
        self.m_or_list.append("(%s)" % clause)

    def filterForUid(self, uid):
        """Only shows files for a specific uid."""
        self.addAndClause("uid = %i" % uid)

    def filterForGid(self, gid):
        """Only shows files for a specific uid."""
        self.addAndClause("gid = %i" % gid)

    def filterForDirectory(self, dir):
        """Only show files in a specific directory"""
        # this uses json.dumps for escaping the query
        self.addAndClause("path = %s" % self.escapeStr(dir))

    def clear(self):
        """Clears all applied filters."""
        self.m_or_list = []
        self.m_and_list = []

    def filterForCapabilities(self):
        """Filter for files which have specific capabilities."""
        self.addOrClause("caps != 0")

    def filterForUmask(self, umask):
        """This will only show files which have at least one of the bits from umask set."""
        self.addOrClause('(mode & %s) != 0' % hex(umask))

    def exclusiveUmask(self, umask):
        """This will filter all files which do not have all bits from the umask set."""
        umask_hex = hex(umask)
        self.addAndClause('(mode & %s) == %s' % (umask_hex, umask_hex))

    def filterForType(self, type):
        """Only allows files of a specific type."""
        self.addAndClause("type = %s" % self.escapeStr(type))

    def escapeStr(self, input):
        """Escapes a string for usage in a database query. Quotes will be automatically added."""
        # this should escape all strings as far as sqlite is concerned
        return json.dumps(str(input))


class FilesystemIterator(object):
    """This class allows iteration of all the files returned by a query to the FS."""

    def __init__(self, cursor):
        self.m_cursor = cursor
        self.m_has_next = True

    def hasNext(self):
        return self.m_has_next

    def next(self):
        item = self.m_cursor.fetchone()

        if item is None:
            self.m_has_next = False
            return False

        self.id = item[0]
        self.parent = item[1]

        self.uid = item[2]
        self.gid = item[3]

        self.caps = item[4]
        self.mode = item[5]
        self.type = item[6]

        self.name = item[7]
        self.basepath = item[8]

        # caps = self.m_cap_translator.getCapStrings(item[4])
        # cap_str = "|".join(caps)

        return True

    def getFullPath(self):
        """Returns the full file path including filename."""
        return os.path.join(self.basepath, self.name)

    def getPermissionString(self):
        """Returns a string describing the mode string."""
        return file_mode.getModeString(self.mode)

    def getTypeLabel(self):
        """Returns the full name of the file type."""
        return file_mode.getTypeLabel(self.mode)
