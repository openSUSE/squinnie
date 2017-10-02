#!/usr/bin/env python2
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

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
import json
import sys
import os

import sscanner.helper
import sscanner.errors


class CapTranslator(object):

    m_capfile = "cap_data.json"

    def __init__(self, file_name = None):
        self.file_name = file_name if file_name else self.m_capfile
        self.cap_data = self.getCapData()

    def isBitSet(self, val, n):
        return 0 != val & (1 << n)

    def getCapStrings(self, cap_integer):

        result = []

        for cap_name, index in self.cap_data.items():
            if self.isBitSet(cap_integer, index):
                result.append(cap_name)

        return result

    def getCapData(self):

        thisdir = os.path.dirname(__file__)
        datadir = os.path.join( thisdir, os.path.pardir, "etc" )
        capfile = os.path.join( datadir, self.file_name )

        if not os.path.exists(capfile):
            raise sscanner.errors.ScannerError(
                "Missing capability description file at {}".format(capfile)
            )

        with open(capfile, "r") as fi:
            return json.load(fi)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        "cap_translator",
        description="translate a capability bit vector into human readable strings"
    )

    def hexint(val):

        return int(val, 16)

    parser.add_argument(
        "bitvector",
        help="the hexadecimal capability bit vector to translate",
        type=hexint,
    )

    args = parser.parse_args()

    translator = CapTranslator()

    cap_data = translator.getCapData()
    print("\nThe given bit vector maps to the following capabilities:\n")
    for cap in translator.getCapStrings(args.bitvector):
        print("- {}".format(cap))
    print("")


if __name__ == "__main__":
    sscanner.helper.executeMain(main)
