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
from sscanner.daw.helper import CategoryLoader
from sscanner.daw.sockets import FdWrapper


class ProcessData(object):

    def __init__(self, dumpIO, factory):
        """
        :param dumpIO: An instance of sscanner.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_data = {}
        self.m_ll_proc = CategoryLoader("proc_data", self.m_dumpIO)
        # self.m_ll_children = CategoryLoader("children", self.m_dumpIO)
        self.m_ll_parents = CategoryLoader("parents", self.m_dumpIO)
        self.m_daw_factory = factory

    def getProcData(self):
        """Return general process data."""
        return self.m_ll_proc.getData()

    def getParents(self):
        """Return the parents of each process"""
        return self.m_ll_parents.getData()

    # def getChildren(self):
    #     """Return the children of each process"""
    #     return self.m_ll_children.getData()

    def getProcessCount(self):
        """Returns the number of recorded processes for the scanned host"""
        return len(self.getProcData())

    def getAllPids(self):
        """Returns all process ids found on the scanned host"""
        return self.getProcData().keys()

    def getProcessInfo(self, pid):
        """Get the data for a specific process"""
        return self.getProcData()[pid]

    def getChildrenForPid(self, searched_pid):
        """Returns all children for a given pid."""
        return [pid for pid, parent in self.getParents().items() if searched_pid == parent]

    def getFileDescriptorsForPid(self, pid):
        """Returns an instance of FileHandlerWrapper for a given process."""
        data = self.getProcessInfo(pid)
        return FdWrapper(pid, data['open_files'], data['Uid'], data['Gid'], self.m_daw_factory)

