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


def print_process_tree(collected_data_dict):
    """
    Has access to:
    - status
    - parents
    - children
    """

    children_data    = collected_data_dict["children"]
    status_data      = collected_data_dict["status"]
    not_printed_pids = status_data.keys()
    indention_count  = 4
    level = 0
    print_proc_indent(status_data, children_data, not_printed_pids, 1, indention_count, level)
    print_proc_indent(status_data, children_data, not_printed_pids, 2, indention_count, level)

    print("")
    print("")

    assert not not_printed_pids


def parents_to_children(pids, parents):
    children = {}
    for p in pids:
        the_parent = parents[p]
        if not the_parent in children.keys():
            children[the_parent] = []
        children[the_parent].append(p)

    return children


def print_proc_indent(status_data, children_data, not_printed_pids, pid, indention_count, level):
    indenter = indention_count * " "
    result_line = ""

    str_proc = indenter * level + "+---" + str(pid)
    result_line += "".join(str_proc.ljust(25))

    str_Uid = str(status_data[pid]["Uid"])
    result_line += "".join(str_Uid.ljust(30))

    str_Gid = str(status_data[pid]["Gid"])
    result_line += "".join(str_Gid.ljust(30))

    str_Groups = str(status_data[pid]["Groups"])
    result_line += "".join(str_Groups.ljust(15))

    str_Seccomp = str(status_data[pid]["Seccomp"])
    result_line += "".join(str_Seccomp.ljust(10))

    str_CapInh = str(status_data[pid]["CapInh"])
    result_line += "".join(str_CapInh.ljust(5))
    str_CapPrm = str(status_data[pid]["CapPrm"])
    result_line += "".join(str_CapPrm.ljust(15))
    str_CapEff = str(status_data[pid]["CapEff"])
    result_line += "".join(str_CapEff.ljust(15))
    str_CapBnd = str(status_data[pid]["CapBnd"])
    result_line += "".join(str_CapBnd.ljust(15))
    str_CapAmb = str(status_data[pid]["CapAmb"])
    result_line += "".join(str_CapAmb.ljust(5))

    print(result_line)
    not_printed_pids.remove(pid)

    if pid in children_data.keys():
        for c in sorted(children_data[pid]):
            print_proc_indent(status_data, children_data, not_printed_pids, c, indention_count, level+1)


def get_crowbar_config(entry_node):
    group = execnet.Group()
    master = group.makegateway("id=master//python=python%d//ssh=root@%s" % (sys.version_info.major, entry_node))

    cmd = "crowbar machines list"
    exec_cmd = "import os; channel.send(os.popen('%s').read())" % (cmd)
    str_crowbar = master.remote_exec(exec_cmd).receive()

    all_nodes_strs = str_crowbar.split("\n")

    # One newline too much leads to one empty string
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

    collected_data_dict = slave.remote_exec(collector).receive()

    pids = collected_data_dict["status"].keys()
    parents = collected_data_dict["parents"]
    collected_data_dict["children"] = parents_to_children(pids, parents)

    print("There are %d processes running on this host." % len(pids))

    print_process_tree(collected_data_dict)


def scan_entry_node(entry_node):
    group, all_nodes_strs = get_crowbar_config(entry_node)

    scan_generic(entry_node, group)


def scan_all(entry_node):
    group, all_nodes_strs = get_crowbar_config(entry_node)

    for node_str in all_nodes_strs:
        scan_generic(node_str, group)
