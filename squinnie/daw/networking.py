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


class NetworkingWrapper(object):
    """
    This class abstracts all info about network connections including unix sockets.
    """

    PROTOCOLS = ["tcp", "tcp6", "udp", "udp6", "unix", "netlink", "packet"]

    def __init__(self, dumpIO):
        """
        :param dumpIO: An instance of squinnie.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_ll_protos = CategoryLoader("networking", self.m_dumpIO)

    def getProtocols(self):
        """Returns a list of all currently possible protocols."""
        return self.PROTOCOLS

    def getProtocolData(self, protocol):
        """Returns the data for a specific protocol."""
        return self.m_ll_protos.getData()[protocol]

    def getDataForAllProtocols(self):
        """Returns the data for all protocols"""
        return self.m_ll_protos.getData()
