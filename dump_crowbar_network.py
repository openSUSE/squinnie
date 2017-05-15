#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
from collections import OrderedDict
import argparse
import json
import sys
import os



# Local modules
import dump_node_data



# PyPy modules
try:
    import execnet
except ImportError:
    print("The module execnet could not be found. Please use your system's package manager or pip to install it.")
    sys.exit(1)


def get_crowbar_config(entry_node):
    group = execnet.Group()
    master = group.makegateway("id=master//python=python{}//ssh=root@{}".format(sys.version_info.major, entry_node))

    cmd = "crowbar machines list"
    exec_cmd = "import os; channel.send(os.popen('{}').read())".format(cmd)
    str_crowbar = master.remote_exec(exec_cmd).receive()

    all_nodes_strs = str_crowbar.split("\n")

    # One newline too much leads to one empty string
    all_nodes_strs = list(filter(None, all_nodes_strs))
    all_nodes_strs.remove(entry_node)

    return [str(item) for item in all_nodes_strs]



def dump_crowbar_to_file(args):
    if not args.nocache and os.path.isfile(args.output):
        print("Skip another scan because a suitable cache was found.")
        print("You can force rebuilding the cache from scratch using --nocache.")
        print("")
    else:

        entry_node = args.entry

        network_tree = OrderedDict()
        network_tree[entry_node] = get_crowbar_config(entry_node)

        file_name = args.output
        with open(file_name, "w") as fi:
            json.dump(network_tree, fi, indent=4, sort_keys=True)
            print("Wrote to network configuration to {}\n".format(file_name))

        all_nodes_strs = []
        all_nodes_strs.append(entry_node)
        all_nodes_strs += network_tree[entry_node]

        # return [dump_node_data.get_filename(node_str) for node_str in all_nodes_strs]



def main(sys_args):
    description = "Connect to a crowbar node and extract its network configuration as JSON."
    parser = argparse.ArgumentParser(prog=sys_args, description=description)

    description = "The host on which crowbar is running."
    parser.add_argument("-e", "--entry", required=True, type=str, help=description)

    description = "The output file you want your data to be dumped to."
    parser.add_argument("-o", "--output", required=True, type=str, help=description)

    description = "Force overwriting the network file, even if it already exists."
    parser.add_argument("--nocache", action="store_true", help=description)

    args = parser.parse_args()

    dump_crowbar_to_file(args)

if __name__ == "__main__":
    main(sys.argv[0])
