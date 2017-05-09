#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
import codecs
import sys
import argparse
import copy
import re
import os

# Local modules.
import cap_bitstring_name
import file_permissions

error_msg = "The module %s could not be found. Please use your system's package manager or pip to install it."

# PyPy modules
try:
    import yaml
except ImportError:
    print(error_msg % "yaml")
    sys.exit(1)

try:
    import termcolor
except ImportError:
    print(error_msg % "termcolor")
    sys.exit(1)

try:
    from terminaltables import SingleTable
except ImportError:
    print(error_msg % "terminaltables")
    sys.exit(1)



def main():
    description = "View a data dump of any single node."
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)



    description = "The input file to view your dumped data from."
    parser.add_argument("-i", "--input", required=True, type=str, help=description)

    description = "Print more detailed information."
    parser.add_argument("-v", "--verbose", action="store_true", help=description)



    description = "Include kernel threads. Kernel threads are excluded by default."
    parser.add_argument("-k", "--kthreads", action="store_true", help=description)

    description = "Only show data that belongs to the provided pid."
    parser.add_argument("-p", "--pid", type=str, help=description)

    description = "Also print all the children of the process provided by -p/--pid."
    parser.add_argument("--children", action="store_true", help=description)

    description = "Print the parent of the process provided by -p/--pid."
    parser.add_argument("--parent", action="store_true", help=description)

    # TODO

    # description = "Show capabilities as string names rather than bitstrings."
    # parser.add_argument("--cap", action="store_true", help=description)
    #
    # description = "Show detailed information on all open file descriptors."
    # parser.add_argument("--fd", action="store_true", help=description)


    args = parser.parse_args()

    view_data(args)



def view_data(args):

    file_name = args.input

    with codecs.open(file_name, "r", encoding="utf-8") as fi:
        datastructure = yaml.load(fi)
    assert len(datastructure.keys()) == 1

    node_str = datastructure.keys()[0]

    collected_data_dict = datastructure[node_str]

    print("There are %d processes running on this host." % len(collected_data_dict["proc_data"].keys()))
    print("")

    column_headers = [
        "pid",
        "executable",
        # "parameters",
        "user",
        "groups",
        "open real files",
        "open pseudo files",
        "Seccomp",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
    ]

    print_process_tree(collected_data_dict, column_headers, args)



def get_str_rep(collected_data_dict, column, pid, args):

    pid_data = collected_data_dict["proc_data"][pid]
    uid_name = collected_data_dict["uid_name" ]
    gid_name = collected_data_dict["gid_name" ]


    if column == "user":
        user_set = set(pid_data["Uid"])
        if not args.verbose:
            user_set = set(uid_name[item] for item in user_set)
        else:
            user_set = set(item for item in user_set)

        result = "|".join(str(x) for x in user_set)

    elif column == "groups":
        groups_set = set(pid_data["Gid"]) | set(pid_data["Groups"])
        if not args.verbose:
            groups_set = set(gid_name[item] for item in groups_set)
        else:
            groups_set = set(item for item in groups_set)
        result = "|".join(str(x) for x in groups_set)

    elif column[0:3] == "Cap":
        result = "%016x" % pid_data[column]

    elif column == "parameters":
        max_len = 20
        cmdline = pid_data[column]
        if not cmdline:
            cmdline = "<empty>"
        cmdline_chunks = [cmdline[i:i+max_len] for i in range(0, len(cmdline), max_len)]
        if not args.verbose:
            result = cmdline_chunks[0]
        else:
            result = "\n".join(cmdline_chunks)

    elif column == "open real files":
        result = len(pid_data["real_files"].keys())

    elif column == "open pseudo files":
        result = len(pid_data["pseudo_files"].keys())



    elif column in pid_data:
        result = pid_data[column]
    else:
        assert False


    return result



def recursive_proc_tree(children, pid, indention_count, level, recursive):
    """
    Recursive function
    """

    self_row = (pid, level)

    children_rows = []
    # if current pid has children and unless the user does not explicitly want them printed
    if recursive and pid in children.keys():
        for child_pid in sorted(children[pid]):
            children_rows += recursive_proc_tree(children, child_pid, indention_count, level+1, recursive)

    return [self_row] + children_rows



def generate_table(column_headers, proc_tree, str_table_data):

    result_table = []
    result_table.append(column_headers)
    for proc_tuple in proc_tree:
        (pid, level) = proc_tuple

        line = []
        for column in column_headers:

            if column == "pid":
                tmp = ( level * (4 * " ") ) + "+---" + str(pid)
            else:
                tmp = str_table_data[column][pid]
            line.append(tmp)

        result_table.append(line)

    return result_table



def print_process_tree(collected_data_dict, column_headers, args):

    all_pids = collected_data_dict["proc_data"].keys()
    children = collected_data_dict["children"]
    parents  = collected_data_dict["parents"]

    str_table_data = {}
    for column in column_headers:
        if column != "pid":

            str_table_data[column] = {}
            for pid in all_pids:
                str_table_data[column][pid] = get_str_rep(collected_data_dict, column, pid, args)


    indention_count  = 4
    level = 0
    # proc_tree
    # [ [1,0], [400,1], [945,1], [976,2], [1437, 3], ... ]

    proc_tree = []
    if not args.pid:
        proc_tree += recursive_proc_tree(children, 1, indention_count, level, True)
        if args.kthreads:
            proc_tree += recursive_proc_tree(children, 2, indention_count, level, True)
    else:
        single_pid = int(args.pid)
        if args.parent:
            single_pid = parents[single_pid]

        if not single_pid in collected_data_dict["proc_data"]:
            exit("There is no process that has pid %d on this node.\n" % single_pid)

        recursive = args.children
        proc_tree += recursive_proc_tree(children, single_pid, indention_count, level, recursive)


    str_table = generate_table(column_headers, proc_tree, str_table_data)


    # color_table(str_table, color_matrix)

    table = SingleTable(str_table)
    # table.inner_column_border = False
    table.outer_border = False

    print(table.table)



if __name__ == "__main__":
    main()
