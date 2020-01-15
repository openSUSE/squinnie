#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Squinnie - scan a system's security related information
# helper functions for accessing capability name and bit value information

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

# Standard library modules
from __future__ import with_statement
import json
import os

import squinnie.helper
import squinnie.errors


class CapTranslator(object):
    m_capfile = "cap_data.json"

    def __init__(self, file_name=None):
        self.file_name = file_name if file_name else self.m_capfile
        self.cap_data = self.getCapData()

    def isBitSet(self, val, n):
        # check if the n-th bit is set in val
        return 0 != val & (1 << n)

    def getCapStrings(self, cap_integer):
        """
        returns capfile-data as an array
        """
        result = []

        for cap_name, index in self.cap_data.items():
            if self.isBitSet(cap_integer, index):
                result.append(cap_name)

        return result

    def getCapData(self):

        capfile = squinnie.getDataFile(self.file_name)

        if not os.path.exists(capfile):
            raise squinnie.errors.ScannerError(
                "Missing capability description file at {}".format(capfile)
            )

        with open(capfile, "r") as fi:
            return json.load(fi)
