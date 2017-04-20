"""
This script is not intended to be run manually, but via the clsc main script.
"""

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
from collections import OrderedDict
import sys
import json

# PyPy modules
import execnet

# External dependencies
import slave as collector

def get_crowbar_config(entry_node):
    group = execnet.Group()
    master = group.makegateway("id=master//python=python%d//ssh=root@%s" % (sys.version_info.major, entry_node))

    cmd = "crowbar machines list"
    exec_cmd = "import os; channel.send(os.popen('%s').read())" % (cmd)
    str_crowbar = master.remote_exec(exec_cmd).receive()

    # One newline too much leads to one empty string
    all_nodes_strs = str_crowbar.split("\n")
    all_nodes_strs = list(filter(None, all_nodes_strs))

    print("Found the following nodes:")
    for node in all_nodes_strs:
        print(node)
    print("")

    return (group, all_nodes_strs)

def scan_generic(node_str, group):
    print("Node:     "+node_str)
    slave  = group.makegateway("via=master//python=python%d//ssh=root@%s" % (sys.version_info.major, node_str))
    python_cmd = "import os; channel.send(os.uname()[1])"
    str_slave = slave.remote_exec(python_cmd).receive()
    print("Hostname: "+str_slave)

    collected_data_str = slave.remote_exec(collector).receive()
    collected_data = json.loads(collected_data_str, object_pairs_hook=OrderedDict)
    print("There are in total %d processes running on this system." % len(collected_data["status"].keys()))
    print("")

def scan_entry_node(entry_node):
    group, all_nodes_strs = get_crowbar_config(entry_node)

    scan_generic(entry_node, group)

def scan_all(entry_node):
    group, all_nodes_strs = get_crowbar_config(entry_node)

    for node_str in all_nodes_strs:
        scan_generic(node_str, group)
