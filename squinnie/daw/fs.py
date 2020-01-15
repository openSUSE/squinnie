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
from helper import CategoryLoader
import sqlite3
import os.path
import stat
import logging
import json
import squinnie.file_mode as file_mode


class Filesystem(object):
    """This class abstracts the filesystem data."""

    def __init__(self, dumpIO):
        """
        :param dumpIO: An instance of squinnie.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_accessor = FsDatabase(self.m_dumpIO.getDumpDir())
        self.m_socket_cache = SocketCache(self.m_accessor)

    def getAllFsData(self):
        """Returns all raw filesystem data."""
        return self.m_accessor.getFullDump()

    def queryFilesystem(self, fsquery):
        """Returns the result of a query on the filesystem database with the given parameters."""
        return self.m_accessor.executeFsQuery(fsquery)

    def getFileProperties(self, path):
        """Returns the properties of a specific file on the filesystem."""
        path = self.resolvePath(path)
        data = self.m_accessor.getFileProperties(os.path.dirname(path), os.path.basename(path))
        return FsDatabase.dbTupleToArray(data)

    def getSocketProperties(self, path):
        """Returns the properties of a specific socket on the filesystem."""
        return self.m_socket_cache.getSocketProperties(self.resolvePath(path))

    def resolvePath(self, path):
        """
        This method will resolve all symlinks in a path.
        :param path: The path to resolve.
        :return: The resolved path.
        """
        replacement = self.m_accessor.resolveLinkSingle(path)

        while replacement is not None:
            path = str(path).replace(replacement[0], replacement[1])
            replacement = self.m_accessor.resolveLinkSingle(path)

        return path


class FsDatabase(object):
    """This class manages the filesystem database"""
    DB_NAME = 'filesystem.db'

    def __init__(self, path):
        self.m_path = path
        self.m_db = sqlite3.connect(self.getDbPath())

        # usually, python2 uses non-unicode strings, but sqlite does. The probe supplies "normal" strings as well, so we
        # need to setup sqlite to use the built-in string type to avoid errors.
        self.m_db.text_factory = str

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

    def createTables(self):
        """Creates the database table, dropping it beforehand if it exists."""
        self.createInodeTable()
        self.createLinkTable()

    def createInodeTable(self):
        """Creates the inode table, dropping it beforehand if it exists."""
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

    def createLinkTable(self):
        """Creates the links table, dropping it beforehand if it exists."""
        sql = """
        CREATE TABLE "links" (
            "id" INTEGER PRIMARY KEY AUTOINCREMENT,
            "name" TEXT,
            "target" TEXT
        )
        """

        self.m_db.execute('DROP TABLE IF EXISTS "links"')
        self.m_db.execute(sql)

    def insertLink(self, path, target):
        """Creates a new link entry in the database."""
        sql = "INSERT INTO links (name, target) VALUES (?, ?)"
        cursor = self.m_db.cursor()
        cursor.execute(sql, (path, target))

    def resolveLinkSingle(self, path):
        """
        Resolves the first symlink in path. Note that this will not fully resolve the path if it contains several
        symlinks!
        :param path: The path to check for
        :return: A tuple of (link, replacement) if a symlink is found, None otherwise.
        """
        data = self.m_db.execute('SELECT name,target FROM links WHERE ? LIKE name||\'%\';', (path,))
        return data.fetchone()

    def insertRawData(self, fsdata):
        """Inserts the raw data into a new database."""
        self.createTables()

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

                if 'target' in item:  # symlink
                    self.insertLink(os.path.join(dir_path, name), item['target'])

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
        self.addOrClause('uid = -1')
        self.addOrClause('gid = -1')
        self.addOrClause('type = "?"')

    def addAndClause(self, clause):
        """
        Ads a new and clause to the query. WARNING: the string will be inserted into the query unescaped, do not input
        anything from an untrusted source!
        """
        self.m_and_list.append("(%s)" % clause)

    def addOrClause(self, clause):
        """
        Ads a new or clause to the query. WARNING: the string will be inserted into the query unescaped, do not input
        anything from an untrusted source!
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

    def filterFilesWithBits(self, mode):
        """Filters all files which have one or more bits set from mode."""
        self.addAndClause('(mode & %s) == 0' % hex(mode))

    def filterFileMode(self, filemode):
        """Filters for files with this specific mode."""
        # the 0o777 filters the not relevant bits (file type)
        self.addAndClause('(mode & %s) == %s' % (0o777, hex(filemode)))


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


class SocketCache(object):
    """
    This class caches all Socket on the Filesystem. This allows querys for socket permissions to be a lot faster.
    """

    def __init__(self, fs_datbase):
        self.m_fs_database = fs_datbase
        self.m_built = False
        self.m_cache = {}

    def _buildCache(self):
        """This method saves a list of all file properties of sockets in RAM."""
        data = self.m_fs_database.findData('type = "s"')
        for row in data:
            fullname = os.path.join(row[8], row[7])
            self.m_cache[fullname] = FsDatabase.dbTupleToArray(row)

        self.m_built = True

    def getSocketProperties(self, path):
        """Returns the properties of a specific socket on the filesystem."""
        if not self.m_built:
            self._buildCache()

        return self.m_cache[path] if path in self.m_cache else None
