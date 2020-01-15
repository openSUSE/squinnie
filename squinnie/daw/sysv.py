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
import squinnie.file_mode as file_mode
import logging
import datetime


class SysVIPC(object):
    """This class abstracts the SysVIPC communications."""

    # this is the name of the key which contains the id name for each protocol
    IDKEYS = {
        'shm': 'shmid',
        'msg': 'msqid',
        'sem': 'semid'
    }

    def __init__(self, dumpIO, factory):
        """
        :param dumpIO: An instance of squinnie.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_ll_data = CategoryLoader("sysvipc", self.m_dumpIO)
        self.m_daw_factory = factory

    def getSysVIpcData(self):
        """Return the raw sysv ipc data."""
        return self.m_ll_data.getData()

    def getFormattedData(self):
        """
        Returns the data formatted for printing as a table with the columns:
        type\perms\user\group\key\id\ctime\cpid\otime\opid
        """
        data = []
        authmgr = self.m_daw_factory.getAccountWrapper()

        for category, ccons in self.getSysVIpcData().items():
            for cdata in ccons:
                data.append([
                    category,
                    cdata['perms'][-3:],
                    authmgr.getNameForUid(cdata['uid'], ''),
                    authmgr.getNameForGid(cdata['gid'], ''),
                    cdata['key'],
                    cdata[self.IDKEYS[category]],
                    self._formatTimestamp(cdata['ctime']),
                    cdata['cpid'] if 'cpid' in cdata else '',
                    self._formatTimestamp(cdata['atime'] if 'atime' in cdata else cdata.get('otime', '')),
                    cdata['lpid'] if 'lpid' in cdata else ''
                ])

        return data

    @staticmethod
    def _formatTimestamp(ts):
        """Makes a timestamp human-readable."""
        return datetime.datetime.fromtimestamp(
            int(ts)
        ).strftime('%Y-%m-%d %H:%M:%S') if ts else ''
