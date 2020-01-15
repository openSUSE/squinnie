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

from squinnie.daw import ProcessData
from squinnie.daw.sysv import SysVIPC
from squinnie.daw.fs import Filesystem
from squinnie.daw import AccountWrapper
from squinnie.daw import NetworkingWrapper
from squinnie.daw.systemdata import SystemData
from squinnie.daw import NamespaceWrapper
from squinnie.daw import NetworkInterfaceWrapper

class Factory(object):
    """
    This class is a factory for all DAW classes.
    """

    def __init__(self, dumpIO):
        """
        :param dumpIO: An instance of squinnie.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_proc_data = ProcessData(self.m_dumpIO, self)
        self.m_fs_wrapper = Filesystem(self.m_dumpIO)
        self.m_account_wrapper = AccountWrapper(self.m_dumpIO)
        self.m_networking_wrapper = NetworkingWrapper(self.m_dumpIO)
        self.m_sysvipc = SysVIPC(self.m_dumpIO, self)
        self.m_systemdata = SystemData(self.m_dumpIO)
        self.m_nwdeviceiface = NetworkInterfaceWrapper(self.m_dumpIO)
        self.m_namespaces = NamespaceWrapper(self.m_dumpIO)

    def getProcWrapper(self):
        return self.m_proc_data

    def getFsWrapper(self):
        return self.m_fs_wrapper

    def getAccountWrapper(self, uid_gid=None):
        if uid_gid:
            return AccountWrapper(self.m_dumpIO, uid_gid)
        return self.m_account_wrapper

    def getNetworkingWrapper(self):
        return self.m_networking_wrapper

    def getSysVIpcWrapper(self):
        return self.m_sysvipc

    def getSystemDataWrapper(self):
        return self.m_systemdata

    def getNwIfaceInfoWrapper(self):
        return self.m_nwdeviceiface

    def getNamespacesWrapper(self):
        return self.m_namespaces
