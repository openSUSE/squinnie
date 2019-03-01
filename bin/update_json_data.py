#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Hamster - scan a system's security related information
# get available names and corresponding bit values from C headers and
# store it in a JSON encoded format

# Copyright (C) 2018 SUSE LINUX GmbH
#
# Author:     Benjamin Deuter, Jannik Main
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
from terminaltables import AsciiTable
import argparse
import json
import sys
import os
import re

def main():
    default_in_path = "/usr/include/linux"
    mode_config = {
        "capability": ["capability.h", "cap_data.json",
                       "#define (CAP_[A-Z_]+)\s+(\d+)"],
        "bitflags": ["if.h", "bitflag_data.json",
                     "IFF_([A-Z_]+)\s+=\s1<<(\d+)"],
        "nw_types": ["if_arp.h", "type_data.json",
                 "#define ARPHRD_([\w]+)\s+(\d+)"]
    }

    in_lam = lambda a: "/".join((default_in_path, a))
    out_lam = lambda a: os.path.normpath( os.path.join(
            os.path.dirname(__file__), os.path.pardir, "etc", a
            ))
    def addDefaults():
        res = [['mode', 'default input', 'default output']]
        for mode in mode_config:
            desc = []
            val = mode_config[mode]
            desc.append(mode)
            desc.append(in_lam(val[0]))
            desc.append(out_lam(val[1]))
            res.append(desc)
        return res


    description = "{} {}\n{}".format("Update the available names and",
                "corresponding bit values from C headers for a",
                "specified type."
    )
    epilog = "Currently available modes are:"

    table = AsciiTable(addDefaults())
    # Do not use any borders at all
    table.outer_border = False
    table.inner_column_border = False
    table.inner_heading_row_border = False

    epilog = "\n".join((epilog, table.table))
    # RawDescriptionHelpFormatter causes new lines and blank spaces in
    # description to be printed as well.
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description,
            epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)

    description = "select the type to update."
    parser.add_argument('mode', metavar="mode", help=description,
                        choices=mode_config.keys(), type=str)

    description = "The C header used as input file."
    parser.add_argument("-i", "--input", type=str, help=description)

    description = "The output file in JSON format."
    parser.add_argument("-o", "--output", type=str, help=description)

    args = parser.parse_args()

    config = mode_config[args.mode]
    #set default parameters
    arg_in = in_lam(config[0])
    if args.input:
        arg_in = args.input
    arg_out = out_lam(config[1])
    if args.output:
        arg_out = args.output

    try:
        with open(arg_in, "r") as fi:
            file_data = fi.read()
    except EnvironmentError as e:
        exit("Cannot open file {}: {}".format(arg_in, str(e)))

    assert file_data

    # read all system-available capabilities/iface-types/iface-flags from
    # the input file into the dictionary
    regex = re.compile(config[2], re.MULTILINE)
    data = OrderedDict()
    for m in re.finditer(regex, file_data):
        val_int = int(m.group(2))
        val_name = str(m.group(1))
        data [val_name] = val_int
    if not data:
        exit("No {} information found in {}".format(args.mode, arg_in))

    #write dictionary to output file in JSON encoded format
    try:
        with open(arg_out, "w") as fi:
            json.dump(data, fi, indent=4, sort_keys=True)
            print("Wrote {} data to {}\n".format(args.mode, arg_out))
    except EnvironmentError as e:
        exit("Cannot write file {}: {}".format(arg_out, str(e)))

if __name__ == "__main__":
    main()
