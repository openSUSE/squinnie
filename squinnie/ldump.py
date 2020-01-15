#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Squinnie - scan a system's security related information

# Copyright (C) 2017 SUSE LINUX GmbH
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

from squinnie.daw import ProcessData

class LocalDump(object):
    """This class serves as DumpIO class, using given data instead of
    extracting it from files
    """

    def __init__(self, data):
        """
        :param data: The data replacing the dump data extracted one.
        """
        self.m_data = data

    def loadFullDump(self):
        """
        This method loads given data as full dump.
        This method is legacy in DumpIO and should not be called.
        """
        raise Exception("Invalid Method call to LocalDump!")

    def loadCategory(self, category):
        """This method loads the data given to this class
        """
        return self.m_data[category]

class LocalFactory(object):
    """
    This class is a replacement for factory
    """

    def __init__(self, data):
        """
        :dict data: data replacing dump data, formed as file-name value
        """
        self.m_ldump = LocalDump(data)
        self.m_proc_data = ProcessData(self.m_ldump, self)

    def getProcWrapper(self):
        return self.m_proc_data
