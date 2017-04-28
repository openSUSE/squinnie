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
    # building the datastructure is now complete

    # Dump data to the output file using yaml
    if args.output:

        file_name = args.output
        with codecs.open(file_name, "w", encoding="utf-8") as fi:
            yaml.dump(datastructure, fi, default_flow_style=False)

        print("Saved data to %s" % args.output)
        print("")

    # No output file, so we print to stdout
    else:
        for node_str in datastructure.keys():
            print_process_tree(node_str, datastructure, args)


def build_data(node_str, group, args):
    slave  = group.makegateway("via=master//python=python%d//ssh=root@%s" % (sys.version_info.major, node_str))
    collected_data_dict = slave.remote_exec(collector).receive()

    pids = collected_data_dict["status"].keys()
    parents = collected_data_dict["parents"]
    collected_data_dict["children"] = parents_to_children(pids, parents)
    return collected_data_dict


def print_process_tree(node_str, datastructure, args):

    print("Accessing: %s" % node_str)
    collected_data_dict = datastructure[node_str]
    print("Node:     "+node_str)
    print("There are %d processes running on this host." % len(collected_data_dict["status"].keys()))
    print("")

    column_headers = [
        "process tree",
        "Uid",
        "Gid",
        "Groups",
        "Seccomp",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "cmdline",
    ]

    indention_count  = 4
    level = 0

    data_table = []

    data_table.append(column_headers)

    data_table += get_unformatted_table(column_headers, collected_data_dict, 1, indention_count, level)

    if args.kthreads:
        data_table += get_unformatted_table(column_headers, collected_data_dict, 2, indention_count, level)


    print_table_spaces(data_table)

    print("")
    print("")


def print_table_spaces(data_table):

    number_of_columns = len(data_table[0])
    max_data = []
    for i in range(number_of_columns):
        maxchars = 0
        for row in data_table:
            chars_count = len(row[i])
            if chars_count > maxchars:
                maxchars = chars_count
        max_data.append(maxchars)

    for row in data_table:
        for i in range(number_of_columns):
            print(row[i].ljust(max_data[i]), end=" ")
        print("")


def get_unformatted_table(column_headers, collected_data_dict, pid, indention_count, level):
    """
    Recursive function
    """

    children_data    = collected_data_dict["children"]
    status_data      = collected_data_dict["status"]
    open_file_pointers = collected_data_dict["open_file_pointers"]

    indenter = indention_count * " "

    self_row = []
    for column_name in column_headers:
        result = ""
        if column_name in status_data[pid].keys():
            column_data = status_data[pid][column_name]
            if column_name[0:3] == "Cap":
                column_data = '%016x' % column_data
            elif column_name == "cmdline":
                column_data = column_data[:40]
            result_str = str(column_data)

        elif column_name == "process tree":
            result_str = indenter * level + "+---" + str(pid)

        self_row.append(result_str)

    # self_row is now complete !

    children_rows = []

    if pid in children_data.keys(): # if current pid has children
        for child_pid in sorted(children_data[pid]):
            children_rows += get_unformatted_table(column_headers, collected_data_dict, child_pid, indention_count, level+1)
    return [self_row] + children_rows
