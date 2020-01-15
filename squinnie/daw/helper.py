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


class CategoryLoader(object):
    """Loads a category from the filesystem via a DumpIO instance."""

    def __init__(self, category, dumpIO):
        """
        :param category: The name of the category.
        :param dumpIO: An instance of squinnie.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_category = category

    def getData(self):
        """Return the contained data, load if necessary."""
        return self.m_dumpIO.loadCategory(self.m_category)


class LazyLoader(object):
    """Lazily loads a category when required."""

    def __init__(self, category, dumpIO):
        """
        :param category: The name of the category.
        :param dumpIO: An instance of squinnie.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_category = category
        self.m_data = {}

    def _loadData(self):
        """
        Loads the data from the dio class.
        :return:
        """
        self.m_data = self.m_dumpIO.loadCategory(self.m_category)

        if not self.m_data:
            raise Exception("Failed to load data!")

    def _loadDataIfRequired(self):
        """Loads the data from the dio class if it was not already loaded."""
        if not self.m_data:
            self._loadData()

    def getData(self):
        """Return the contained data, load if necessary."""
        self._loadDataIfRequired()
        return self.m_data
