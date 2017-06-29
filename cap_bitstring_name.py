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



class Cap_Translator():

    def __init__(self, file_name):
        self.file_name = file_name
        self.cap_data  = self.get_cap_data()

    def nth_bit_set(self, val, n):
        return 0 != val & (1 << n)

    def get_cap_strings(self, cap_integer):
        result = []

        for cap_name, index in self.cap_data.items():
            if self.nth_bit_set(cap_integer, index):
                result.append(cap_name)

        return result

    def get_cap_data(self):
        if os.path.exists(self.file_name):
            with open(self.file_name, "r") as fi:
                return json.load(fi)
        else:
            exit("The file {} does not exist. Exiting.".format(self.file_name))



def main():
    if len(sys.argv) < 2:
        exit("You have to provide a bitstring.\n")

    file_name = "cap_data.json"
    cap_trans = Cap_Translator(file_name)

    cap_data = cap_trans.get_cap_data()
    print("\nThe given bitstring maps to the following capabilities:\n")
    cap_integer = int(sys.argv[1], 16)
    for cap in cap_trans.get_cap_strings(cap_integer):
        print("- {}".format(cap))
    print("")

if __name__ == "__main__":
    main()
