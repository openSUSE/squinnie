# vim: ts=4 et sw=4 sts=4 :

# security scanner - scan a system's security related information
# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author:     Benjamin Deuter
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

from __future__ import print_function
import sys
import os
import stat

# Copied from Python 3.3 stat._filemode_table, older python versions do not
# include this
_filemode_table = stat._filemode_table if \
    hasattr(stat, '_filemode_table') else (
    ((stat.S_IFLNK,         "l"),
     (stat.S_IFREG,         "-"),
     (stat.S_IFBLK,         "b"),
     (stat.S_IFDIR,         "d"),
     (stat.S_IFCHR,         "c"),
     (stat.S_IFIFO,         "p")),

    ((stat.S_IRUSR,         "r"),),
    ((stat.S_IWUSR,         "w"),),
    ((stat.S_IXUSR|stat.S_ISUID, "s"),
     (stat.S_ISUID,         "S"),
     (stat.S_IXUSR,         "x")),

    ((stat.S_IRGRP,         "r"),),
    ((stat.S_IWGRP,         "w"),),
    ((stat.S_IXGRP|stat.S_ISGID, "s"),
     (stat.S_ISGID,         "S"),
     (stat.S_IXGRP,         "x")),

    ((stat.S_IROTH,         "r"),),
    ((stat.S_IWOTH,         "w"),),
    ((stat.S_IXOTH|stat.S_ISVTX, "t"),
     (stat.S_ISVTX,         "T"),
     (stat.S_IXOTH,         "x"))
)

if hasattr(stat, "filemode"):
    def getModeString(mode):
        return stat.filemode(mode)
else:
    # Copied from Python 3.3
    def getModeString(mode):
        """Convert a file's mode to a string of the form '-rwxrwxrwx'."""
        if not isinstance(mode, int): # Broken symlinks have no permissions
            return "!PERMERROR"

        perm = []
        for table in _filemode_table:
            for bit, char in table:
                if mode & bit == bit:
                    perm.append(char)
                    break
            else:
                perm.append("-")
        return "".join(perm)

def getTypeLabel(mode):
    """Returns a label for the file type found in ``mode``."""

    if mode == None:
        return "!MODEERROR!"

    if stat.S_ISDIR(mode):
        return "directory"
    elif stat.S_ISREG(mode):
        return "regular file"
    elif stat.S_ISLNK(mode):
        return "symbolic link"
    elif stat.S_ISFIFO(mode):
        return "FIFO (named pipe)"
    elif stat.S_ISSOCK(mode):
        return "socket"
    elif stat.S_ISCHR(mode):
        return "character special device file"
    elif stat.S_ISBLK(mode):
        return "block special device file"

def permReadable(file_perm):
    """
    Get access permission as integer
    Output boolean whether access permissions grant read access
    """

    return (file_perm & 4) != 0

def canAccessFile(user_perms, file_perms, file_mode):
    """Returns a boolean whether a user owning ``user_perms`` can
    read-access a file having the given ``file_perms`` and ``file_mode``.

    :param dict user_perms: For example {"Uid": 638, "gid_set": [123, 456]}
    :param dict file_perms: For example {"Uid": 378, "Gid": 547}
    :param dict file_mode: For example {"Uid": 123, "Gid": 456, "other": 789}
    """

    # uid
    if file_perms["Uid"] == user_perms["Uid"]:
        if permReadable(file_mode["Uid"]):
            return True

    # gid
    elif file_perms["Gid"] in user_perms["Gid_set"]:
        if permReadable(file_mode["Gid"]):
            return True

    # other
    else:
        if permReadable(file_mode["other"]):
            return True

    return False

def getFdFlagLabels(flags):
    """Returns a list of labels corresponding to the file descriptors
    flags."""
    result = []

    # Only available since Python 3.3
    if not hasattr(os, "O_CLOEXEC"):
        os.O_CLOEXEC = 524288

    if flags & os.O_WRONLY:
        result.append("O_WRONLY")
    if flags & os.O_RDWR:
        result.append("O_RDWR")
    if flags & os.O_CLOEXEC:
        result.append("O_CLOEXEC")

    return result

