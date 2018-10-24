#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# security scanner - scan a system's security related information
# get available names and corresponding bit values from C headers and
# store it in a JSON encoded format

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
from collections import OrderedDict
import argparse
import json
import sys
import os
import re

def main():
    description = "Update the file capability bit information generated from capability.h"
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)

    default_in = "/usr/include/linux/capability.h"
    description = "The capability.h file. If not provided, {} will be used.".format(default_in)
    parser.add_argument(
        "-i", "--input", type=str, help=description,
        default = default_in
    )

    default_out = os.path.normpath( os.path.join(
        os.path.dirname(__file__), os.path.pardir, "etc", "cap_data.json"
    ))
    description = "The output file for capability configuration in JSON format. If not provided, {} will be used.".format(default_out)
    parser.add_argument(
        "-o", "--output", type=str, help=description,
        default = default_out
    )

    args = parser.parse_args()

    in_path = args.input

    try:
        with open(in_path, "r") as fi:
            file_data = fi.read()
    except EnvironmentError as e:
        exit("Cannot open file {}: {}".format(in_path, str(e)))

    assert file_data

    # read all system-available capabilities from the input file into the dictionary

    regex = re.compile("#define (CAP_[A-Z_]+)\s+(\d+)", re.MULTILINE)

    cap_data = OrderedDict()
    for m in re.finditer(regex, file_data):
        cap_int  = int(m.group(2))
        cap_name = str(m.group(1))
        cap_data[cap_name] = cap_int

    if not cap_data:
        exit("No capability information found in {}".format(in_path))

    # writes cap_data dictionary to output file in JSON encoded format
    try:
        with open(args.output, "w") as fi:
            json.dump(cap_data, fi, indent=4, sort_keys=True)
            print("Wrote capability data to {}\n".format(args.output))
    except EnvironmentError as e:
        exit("Cannot write file {}: {}".format(args.output, str(e)))

if __name__ == "__main__":
    main()
