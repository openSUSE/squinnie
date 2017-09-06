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

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
from collections import OrderedDict
import argparse
import json
import sys
import os

# Non-standard modules
import termcolor

# Local modules
import helper
from helper import eprint

# PyPy modules
try:
    import execnet
except ImportError:
    helper.missingModule("execnet")

class Crowbar(object):

    def __init__(self, args):

        self.m_args = args

    def _haveCache(self):

        use_cache = not self.m_args.nocache 

        return use_cache and os.path.isfile(self.m_args.output)

    def get_crowbar_config(self):
        """
        Creates a connection to the configured entry node and retrieves a
        machine listing from crowbar running there.
        """

        entry_node = self.m_args.entry
        if not entry_node:
            raise Exception("entry_node is required")

        group = execnet.Group()
        master = group.makegateway("id=master//python=python{}//ssh=root@{}".format(2, entry_node))

        cmd = "crowbar machines list"
        exec_cmd = "import subprocess; channel.send(subprocess.check_output('{}'))".format(cmd)
        try:
            str_crowbar = master.remote_exec(exec_cmd).receive()
        except execnet.RemoteError as e:
            raise Exception("Failed to run crowbar on {}:\n\n{}".format(
                entry_node, e
            ))

        all_nodes_strs = str_crowbar.split("\n")

        # One newline too much leads to one empty string
        all_nodes_strs = list(filter(None, all_nodes_strs))
        try:
            all_nodes_strs.remove(entry_node)
        except ValueError:
            raise Exception("entry_node was not found in returned crowbar data")

        return [str(item) for item in all_nodes_strs]

    def dump_crowbar_to_file(self):

        # TODO: in the cached case we're not actually dumping something to
        # file, so maybe we should split this function?
        if self._haveCache():
            # TODO: reading the cached data should be in this module, too, no?
            import dump_node_data
            cache = self.m_args.output
            eprint("Using cached crowbar network data from", cache)

            tree_dict_str = dump_node_data.read_network_config(cache)
            entry_node = tree_dict_str.keys()[0]

            return entry_node
        else:

            entry_node = self.m_args.entry

            network_tree = OrderedDict()
            network_tree[entry_node] = self.get_crowbar_config()

            file_name = self.m_args.output
            with open(file_name, "w") as fi:
                json.dump(network_tree, fi, indent=4, sort_keys=True)
                print("Wrote crowbar network data to {}\n".format(file_name))

            all_nodes_strs = []
            all_nodes_strs.append(entry_node)
            all_nodes_strs += network_tree[entry_node]

            return entry_node

def main():
    description = "Connect to a crowbar node via SSH and extract its network configuration as JSON."
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)

    description = "The host on which crowbar is running."
    parser.add_argument("-e", "--entry", required=True, type=str, help=description)

    description = "The output file you want your data to be dumped to."
    parser.add_argument("-o", "--output", required=True, type=str, help=description)

    description = "Force overwriting the network file, even if it already exists."
    parser.add_argument("--nocache", action="store_true", help=description)

    args = parser.parse_args()

    crowbar = Crowbar(args)
    crowbar.dump_crowbar_to_file()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(termcolor.colored("Error:", 'red'), str(e))
        sys.exit(1)
