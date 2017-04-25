"""
This script is not intended to be run manually, but via the clsc main script.
"""

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
from collections import OrderedDict
import sys
import codecs

# PyPy modules
import execnet
import termcolor
import yaml

# External dependencies
import slave as collector

# http://stackoverflow.com/questions/3787908/python-determine-if-all-items-of-a-list-are-the-same-item
def all_same(items):
    return all(x == items[0] for x in items)

def parents_to_children(pids, parents):
    children = {}
    for p in pids:
        the_parent = parents[p]
        if not the_parent in children.keys():
            children[the_parent] = []
        children[the_parent].append(p)

    return children

def get_cap_str(status_data_pid, cap_str, the_len):
    current_cap = '%016x' % status_data_pid[cap_str]
    result = "".join(current_cap.ljust(the_len))
    if 0 not in status_data_pid["Uid"] and 0 not in status_data_pid["Gid"]:
        if status_data_pid[cap_str] != 0:
            result = termcolor.colored(result, 'green', 'on_red')
    return result


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



def produce_global_datastructure(args):

    datastructure = {}

    # Use input file, no need for scanning again
    if args.input:
        file_name = args.input
        with codecs.open(file_name, "r", encoding="utf-8") as fi:
            datastructure = yaml.load(fi)

    # No input file, so we have to scan
    else:
        group, all_nodes_strs = get_crowbar_config(args.entry)
        if not args.all:
            node_str = args.entry
            datastructure[node_str] = build_data(node_str, group, args)
        else:
            for node_str in all_nodes_strs:
                datastructure[node_str] = build_data(node_str, group, args)
    # data_structure is now complete

    # Dump data to the output file using yaml
    if args.output:

        file_name = args.output
        with codecs.open(file_name, "w", encoding="utf-8") as fi:
            yaml.dump(datastructure, fi, default_flow_style=False)

    # No output file, so we print to stdout
    else:
        if not args.all:
            collected_data_dict = datastructure[args.entry]
            print_process_tree(collected_data_dict, args)
        else:
            for node_str in all_nodes_strs:
                collected_data_dict = datastructure[node_str]
                print_process_tree(collected_data_dict, args)





def build_data(node_str, group, args):
    collected_data_dict = scan_once(node_str, group, args)
    pids = collected_data_dict["status"].keys()
    parents = collected_data_dict["parents"]
    collected_data_dict["children"] = parents_to_children(pids, parents)
    return collected_data_dict



def scan_once(node_str, group, args):
    print("Node:     "+node_str)
    slave  = group.makegateway("via=master//python=python%d//ssh=root@%s" % (sys.version_info.major, node_str))
    python_cmd = "import os; channel.send(os.uname()[1])"
    str_slave = slave.remote_exec(python_cmd).receive()
    print("Hostname: "+str_slave)

    collected_data_dict = slave.remote_exec(collector).receive()


    print("There are %d processes running on this host." % len(collected_data_dict["status"].keys()))

    return collected_data_dict


def print_process_tree(collected_data_dict, args):

    # not_printed_pids will be consecutively emptied
    not_printed_pids = collected_data_dict["status"].keys()
    indention_count  = 4
    level = 0

    print_proc_indent(collected_data_dict, not_printed_pids, 1, indention_count, level)

    if args.kthreads:
        print_proc_indent(collected_data_dict, not_printed_pids, 2, indention_count, level)
        assert not not_printed_pids

    print("")
    print("")


def print_proc_indent(collected_data_dict, not_printed_pids, pid, indention_count, level):
    """
    Recursive function
    """

    children_data    = collected_data_dict["children"]
    status_data      = collected_data_dict["status"]
    open_file_pointers = collected_data_dict["open_file_pointers"]

    indenter = indention_count * " "
    result_line = ""

    str_proc = indenter * level + "+---" + str(pid)
    result_line += "".join(str_proc.ljust(30))

    str_fp = str(len(open_file_pointers[pid]))
    str_fp = "".join(str_fp.ljust(3))
    result_line += str_fp

    str_Uid = str(status_data[pid]["Uid"])
    str_Uid = "".join(str_Uid.ljust(25))
    if not all_same(status_data[pid]["Uid"]):
        str_Uid = termcolor.colored(str_Uid, 'green', 'on_red')
    result_line += str_Uid

    str_Gid = str(status_data[pid]["Gid"])
    str_Gid = "".join(str_Gid.ljust(28))
    if not all_same(status_data[pid]["Gid"]):
        str_Gid = termcolor.colored(str_Gid, 'green', 'on_red')
    result_line += str_Gid

    str_Groups = str(status_data[pid]["Groups"])
    result_line += "".join(str_Groups.ljust(15))

    str_Seccomp = str(status_data[pid]["Seccomp"])
    str_Seccomp = "".join(str_Seccomp.ljust(6))
    if status_data[pid]["Seccomp"]:
        str_Seccomp = termcolor.colored(str_Seccomp, 'green', 'on_red')
    result_line += str_Seccomp

    result_line += get_cap_str(status_data[pid], "CapInh", 17)
    result_line += get_cap_str(status_data[pid], "CapPrm", 17)
    result_line += get_cap_str(status_data[pid], "CapEff", 17)
    result_line += get_cap_str(status_data[pid], "CapBnd", 17)
    result_line += get_cap_str(status_data[pid], "CapAmb", 17)

    print(result_line)
    not_printed_pids.remove(pid)

    if pid in children_data.keys():
        for c in sorted(children_data[pid]):
            print_proc_indent(collected_data_dict, not_printed_pids, c, indention_count, level+1)
