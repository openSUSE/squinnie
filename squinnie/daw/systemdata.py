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
import logging
import datetime


class SystemData(object):
    """This class abstracts the SysVIPC communications."""

    def __init__(self, dumpIO):
        """
        :param dumpIO: An instance of squinnie.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_ll_data = CategoryLoader("systemdata", self.m_dumpIO)

    def getSysconfData(self):
        """
        Returns all sysconfig values/
        """
        return self.m_ll_data.getData()['sysconf']

    def getSystemUptime(self):
        """
        Returns the uptime of the system at the time of scanning in seconds.
        """
        return float(self.m_ll_data.getData()['uptime'])

    def getMountinfo(self):
        """
        Returns information about all mounted filesystems.
        """
        return self.m_ll_data.getData()['mounts']

    def getProcessUptime(self, ticks):
        """
        Returns the time a process has been running for in seconds.
        :param ticks: The ticks as given in /proc/<pid>/stat
        :return: The runtime in seconds.
        """
        # the tick count in stat is the time in ticks the process has been started
        # so, at first, we need to convert the ticks to seconds:
        seconds_at_start = float(ticks) / float(self.getSysconfData()['SC_CLK_TCK'])

        # so now, we need to substract the starttime from the uptime to get the actual runtime
        return self.getSystemUptime() - seconds_at_start

    def getShmData(self):
        """
        Returns the shm data as dict array with inode and names.
        :return:
        """
        return self.m_ll_data.getData()['shm']

    def getNameForShmInode(self, inode):
        """
        Returns the name of a shm or semaphore in /dev/shm by inode.
        :param inode: The inode to search for.
        :return: The name as a string.
        """
        for item in self.getShmData():
            if item['inode'] == int(inode):
                return item['name']
        return None
