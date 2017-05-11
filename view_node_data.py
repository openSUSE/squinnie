#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
import cPickle as pickle
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
    import terminaltables
except ImportError:
    print(error_msg % "terminaltables")
    sys.exit(1)



def main(sys_args):
    description = "View a data dump of any single node."
    parser = argparse.ArgumentParser(prog=sys_args, description=description)



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



    description = "Show capabilities as string names rather than bitstrings."
    parser.add_argument("--cap", action="store_true", help=description)



    description = "Show detailed information on all open ordinary files."
    parser.add_argument("--realfiles", action="store_true", help=description)

    description = "Show detailed information on all open pseudo files, such as pipes, sockets and or inodes."
    parser.add_argument("--pseudofiles", action="store_true", help=description)


    args = parser.parse_args()

    view_data(args)



def view_data(args):

    file_name = args.input

    with open(file_name, "r") as fi:
        datastructure = pickle.load(fi)
    assert len(datastructure.keys()) == 1

    node_str = list(datastructure.keys())[0]

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

    print("")



def get_pseudo_file_str_rep(raw_pseudo_file_str):

    # Convert fds to more easy-to-read strings
    regex = re.compile("\/proc\/\d+\/fd\/(socket|pipe|anon\_inode)+:\[(\w+)\]")
    match = re.match(regex, raw_pseudo_file_str)

    if match:
        the_type  = match.group(1)
        the_value = match.group(2)

        if the_type == "pipe":
            result = "%s : %s" % (the_type, the_value)
        elif the_type == "socket":
            result = "%s : %s" % (the_type, the_value)
        elif the_type == "anon_inode":
            result = "%s : %s" % (the_type, the_value)
        else:
            assert False
        return result
    else:
        assert False



def get_str_rep(collected_data_dict, column, pid, args):

    pid_data = collected_data_dict["proc_data"][pid]
    uid_name = collected_data_dict["uid_name" ]
    gid_name = collected_data_dict["gid_name" ]

    all_uids_equal = len(set(pid_data["Uid"])) == 1
    all_gids_equal = len(set(pid_data["Gid"])) == 1


    if column == "user":
        user_set = set()
        for item in set(pid_data["Uid"]):
            user_set.add(uid_name[item] if not args.verbose else "%s(%s)" % (uid_name[item], item))
        result = "|".join(str(x) for x in user_set)
        if not all_uids_equal:
            result.get_color_str(result)

    elif column == "groups":
        groups_set = set(pid_data["Gid"]) | set(pid_data["Groups"])
        groups_set_str = set()
        for item in groups_set:
            groups_set_str.add(gid_name[item] if not args.verbose else "%s(%s)" % (uid_name[item], item))
        result = "|".join(str(x) for x in groups_set_str)
        if not all_gids_equal:
            result.get_color_str(result)

    elif column == "Seccomp":
        result = "" if not args.verbose else get_color_str(pid_data[column])

    elif column[0:3] == "Cap":
        boring_cap_values = [0, 274877906943]
        all_uids_are_root = all_uids_equal and pid_data["Uid"][0] == 0
        no_uids_are_root = pid_data["Uid"].count(0) == 0

        if all_uids_are_root:
            result = ""
        elif not args.verbose and pid_data[column] in boring_cap_values:
            result = ""
        else:
            if not args.cap:
                result = "%016x" % pid_data[column]

                # Now color it if necessary
                if no_uids_are_root:
                    result = get_color_str(result)
            else:
                cap_trans = cap_bitstring_name.Cap_Translator("cap_data.json")
                result = "\n".join(cap_trans.get_cap_strings(pid_data[column]))

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
        if not args.realfiles:
            result = len(pid_data["real_files"].keys())
        else:
            real_files_str = [rf_str for rf_str in pid_data["real_files"].keys()]
            result = "\n".join(sorted(real_files_str))

    elif column == "open pseudo files":
        if not args.pseudofiles:
            result = len(pid_data["pseudo_files"].keys())
        else:
            pseudo_files_str = []
            for pf_str in pid_data["pseudo_files"].keys():
                if not args.verbose:
                    pseudo_files_str.append(get_pseudo_file_str_rep(pf_str))
                else:
                    pseudo_files_str.append(pf_str)
            result = "\n".join(sorted(pseudo_files_str))

    elif column in pid_data:
        result = pid_data[column]
    else:
        assert False


    return result



def color_if_necessary(collected_data_dict, column, pid, args, tmp_str):
    pid_data = collected_data_dict["proc_data"][pid]
    uid_name = collected_data_dict["uid_name" ]
    gid_name = collected_data_dict["gid_name" ]

    if column[0:3] == "Cap":
        if tmp_str != "":
            if not args.cap:
                result = get_color_str(tmp_str)
            else:
                all_caps = tmp_str.split("\n")

                # for (cap_str, cap_int) in zip(all_caps, pid_data[column]):
                #     if : # TODO: Here condition
                #
                #
                #
                # # TODO
                # # result is the new string
                # # we need access to the old string


    elif column in pid_data:
        result = pid_data[column]
    else:
        assert False

    return result



def get_color_str(a_string):
    return "^%s^" % a_string



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
    to_remove = set()
    for column in column_headers:
        if column != "pid":

            str_table_data[column] = {}
            for pid in all_pids:
                tmp_str = get_str_rep(collected_data_dict, column, pid, args)
                # tmp_str = color_if_necessary(collected_data_dict, column, pid, args, tmp_str)
                str_table_data[column][pid] = tmp_str

            column_values = list(str_table_data[column].values())
            if len(set(column_values)) == 1 and column_values[0] == "":
                to_remove.add(column)

    # These values are generally uninteresting
    to_remove.add("CapAmb")
    to_remove.add("CapBnd")


    # Remove empty columns since they only take up unnecessary space
    for empty_column in to_remove:
        column_headers.remove(empty_column)


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

    # Note: If this ever gets ported to Python 3, consider changing to this
    # to DoubleTable which makes use of box-drawing characters that are much
    # more pleasing to look at.
    # Unfortunately, using this under Python 2 breaks output using less and grep
    table = terminaltables.AsciiTable(str_table)

    table.inner_column_border = False
    table.outer_border = False

    print(table.table)



if __name__ == "__main__":
    main(sys.argv[0])
