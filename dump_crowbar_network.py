#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
import codecs
import sys
import argparse
import json
from collections import OrderedDict

# PyPy modules
try:
    import execnet
except ImportError:
    print("The module execnet could not be found. Please use your system's package manager or pip to install it.")
    sys.exit(1)


def get_crowbar_config(entry_node):
    group = execnet.Group()
    master = group.makegateway("id=master//python=python%d//ssh=root@%s" % (sys.version_info.major, entry_node))

    cmd = "crowbar machines list"
    exec_cmd = "import os; channel.send(os.popen('%s').read())" % (cmd)
    str_crowbar = master.remote_exec(exec_cmd).receive()

    all_nodes_strs = str_crowbar.split("\n")

    # One newline too much leads to one empty string
    all_nodes_strs = list(filter(None, all_nodes_strs))
    all_nodes_strs.remove(entry_node)

    return all_nodes_strs



def dump_crowbar_to_file(args):
    entry_node = args.entry

    network_tree = OrderedDict()
    network_tree[entry_node] = get_crowbar_config(entry_node)

    file_name = args.output
    with codecs.open(file_name, "w", encoding="utf-8") as fi:
        json.dump(network_tree, fi, indent=4, sort_keys=True)
        print("Wrote to network configuration to %s\n" % file_name)

    all_nodes = []
    all_nodes.append(entry_node)
    all_nodes.append(network_tree[entry_node])

    return all_nodes



def main(sys_args):
    description = "Connect to a crowbar node and extract its network configuration as JSON."
    parser = argparse.ArgumentParser(prog=sys_args, description=description)

    description = "The host on which crowbar is running."
    parser.add_argument("-e", "--entry", required=True, type=str, help=description)

    description = "The output file you want your data to be dumped to."
    parser.add_argument("-o", "--output", required=True, type=str, help=description)

    args = parser.parse_args()

    dump_crowbar_to_file(args)

if __name__ == "__main__":
    main(sys.argv[0])
