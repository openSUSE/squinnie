#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Copyright (C) 2018 SUSE LINUX GmbH
#
# Author: Jannik Main
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

class NetworkInterfaceWrapper(object):
    """
    This class abstracts all information about network interfaces
    """

    def __init__(self, dumpIO):
        """
        :param dumpIO: An instance of squinnie.dio.DumpIO
        """
        self.m_dumpIO = dumpIO
        self.m_data = CategoryLoader("nwifaces", self.m_dumpIO)

    def getAllNwIfaceData(self):
        return self.m_data.getData()
