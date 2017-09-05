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
import sys
import argparse
import stat
import copy
import re
import os
import termcolor

# Local modules.
import sscanner.cap_translator as cap_translator
import sscanner.helper as helper
pickle = helper.importPickle()
import sscanner.file_mode as file_mode

error_msg = "The module {} could not be found. Please use your system's package manager or pip to install it."

# PyPy modules
try:
    import terminaltables
except ImportError:
    print(error_msg.format("terminaltables"))
    sys.exit(1)



def main():
    description = "View a data dump of any single node."
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)



    description = "The input file to view your dumped data from."
    parser.add_argument("-i", "--input", required=True, type=str, help=description)

    description = "Print more detailed information."
    parser.add_argument("-v", "--verbose", action="store_true", help=description)



    description = "Show parameters from the executable cmdline variable."
    parser.add_argument("--params", action="store_true", help=description)

    description = "Include kernel threads. Kernel threads are excluded by default."
    parser.add_argument("-k", "--kthreads", action="store_true", help=description)

    description = "Only show data that belongs to the provided pid."
    parser.add_argument("-p", "--pid", type=str, help=description)

    description = "Also print all the children of the process provided by -p/--pid."
    parser.add_argument("--children", action="store_true", help=description)

    description = "Print the parent of the process provided by -p/--pid."
    parser.add_argument("--parent", action="store_true", help=description)

    description = "Show all open file descriptors for every process."
    parser.add_argument("--fd", action="store_true", help=description)

    description = "Show only the open file descriptors in a dedicated view and nothing else."
    parser.add_argument("--onlyfd", action="store_true", help=description)

    description = "View alle files on the file system, including their permissions."
    parser.add_argument("--filesystem", action="store_true", help=description)


    args = parser.parse_args()

    view_data(args)



def get_term_width():
    return int(os.popen('stty size', 'r').read().split()[1])



def view_data(args):

    file_name = args.input

    try:
        with open(file_name, "rb") as fi:
            datastructure = pickle.load(fi)
    except Exception as e:
        if isinstance(e, EOFError):
            # on python2 no sensible error string is contained in EOFError
            e = "Premature end of file"
        exit("Failed to load node data from {}: {}".format(file_name, str(e)))
    sys.stdout.flush()
    assert len(datastructure.keys()) == 1

    node_str = list(datastructure.keys())[0]
    collected_data_dict = datastructure[node_str]

    if args.onlyfd: # file descriptor view
        print_only_file_descriptors(collected_data_dict, args)
    elif args.filesystem:
        str_table = []
        get_filesystem_table(str_table, collected_data_dict["filesystem"], collected_data_dict["uid_name" ], collected_data_dict["gid_name" ], "/", args)

        width_column_dict = build_width_column_dict(str_table)
        term_width = get_term_width()
        print_table_width_column_dict(str_table, width_column_dict, term_width)

    else: # process tree view
        print("There are {} processes running on this host.".format(len(collected_data_dict["proc_data"].keys())))
        print("")
        column_headers = [
            "pid",
            "executable",
            "parameters",
            "user",
            "groups",
            "open file descriptors",
            "features",
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
        ]
        print_process_tree(collected_data_dict, column_headers, args)

    print("")




def build_width_column_dict(str_table):
    width_column_dict = {}
    for i in range(len(str_table[0])):
        width_column_dict[i] = max(len(row[i]) for row in str_table)

    return width_column_dict



def print_table_width_column_dict(str_table, width_column_dict, max_width):
    for row in str_table:
        to_print = " ".join(row[i].ljust(width_column_dict[i]) for i in range(len(str_table[0])))
        if sys.stdout.isatty():
            print(to_print[:max_width])
        else:
            print(to_print)



def get_file_properties(filesystem, filename):
    tokens = filename[1:].split("/")
    last = tokens.pop()
    current_fs = filesystem
    try:
        while tokens:
            t = tokens.pop(0)
            current_fs = current_fs[t]["subitems"]
        result = current_fs[last]["properties"]["st_mode"]
    except KeyError:
        result = "_PERMERROR"

    return result



def get_filesystem_table(datastructure, filesystem, uid_name, gid_name, base_path, args):
    """
    Note: This is a recursive function
    """

    for item_name, item_val in sorted(filesystem.items()):
        base_path_file = os.path.join(base_path, item_name)
        item_properties = item_val["properties"]
        perm_str      = file_mode.get_mode_string(item_properties["st_mode"])
        file_type_str = file_mode.get_type_label(item_properties["st_mode"])

        if item_properties["st_uid"] == None or item_properties["st_uid"] not in uid_name:
            user  = "!USERERROR!"
        else:
            user  = uid_name[item_properties["st_uid"]]

        if item_properties["st_gid"] == None or item_properties["st_gid"] not in gid_name:
            group = "!GROUPERROR!"
        else:
            group = gid_name[item_properties["st_gid"]]


        cap_trans = cap_translator.CapTranslator("cap_data.json")
        cap_str = "|".join(cap_trans.get_cap_strings(item_properties["caps"]))

        datastructure.append([perm_str, base_path_file, file_type_str, user, group, cap_str])

        if "subitems" in item_val:
            get_filesystem_table(datastructure, item_val["subitems"], uid_name, gid_name, base_path_file, args)
        else:
            base_path_file = base_path



def print_only_file_descriptors(collected_data_dict, args):
    all_pids = collected_data_dict["proc_data"].keys()

    for pid in sorted(all_pids):
        open_file_count = len(collected_data_dict["proc_data"][pid]["open_files"].keys())

        # Hide the process if it has no open files
        # But always show all processes on -v
        if open_file_count > 0 or args.verbose:
            print("{} (pid: {})".format(collected_data_dict["proc_data"][pid]["executable"], pid))
            print("----")
            list_str = get_list_of_open_file_descriptors(collected_data_dict, pid, args)
            print(list_str)
            print("")



def inode_to_identifier(collected_data_dict, inode):
    """
    Return the string representation of an inode number, according to the
    network lookup tables
    """
    result = ""

    result = []
    for transport_protocol in ["tcp", "tcp6", "udp", "udp6", "unix"]:
        if transport_protocol in collected_data_dict:
            if inode in collected_data_dict[transport_protocol]:
                if transport_protocol == "unix": # unix domain socket
                    the_identifier = collected_data_dict[transport_protocol][inode]
                    if the_identifier == "": # unnamed unix domain socket
                        the_identifier = "<unnamed>"
                    else: # else: named or abstract unix domain socket
                        st_mode = get_file_properties(collected_data_dict["filesystem"], the_identifier)
                        if st_mode:
                            permissions = file_mode.get_mode_string(st_mode)
                        else:
                            permissions = st_mode
                        the_identifier = "{} (named socket file permissions: {})".format(the_identifier, permissions)
                else: # TCP or UDP socket
                    the_identifier = int(collected_data_dict[transport_protocol][inode][0][1], 16) # port of the local ip
                result.append("{}:{}".format(transport_protocol, the_identifier))


    result = "|".join(result)

    if result != "":
        return result
    else:
        return "<port not found, inode: {:>15}>".format(inode)



def get_pseudo_file_str_rep(collected_data_dict, raw_pseudo_file_str):
    """
    Return the supplied file path in addition its file type
    """

    # Convert fds to more easy-to-read strings
    regex = re.compile("\/proc\/\d+\/fd\/(socket|pipe|anon\_inode)+:\[?(\w+)\]?")
    match = re.match(regex, raw_pseudo_file_str)

    if match:
        the_type  = match.group(1)
        the_value = match.group(2)

        if the_type == "pipe":
            result = "{} : {:>10}".format(the_type, the_value)
        elif the_type == "socket":
            result = "{} : {:>10}".format(the_type, inode_to_identifier(collected_data_dict, the_value))
        elif the_type == "anon_inode":
            result = "{} : {}".format(the_type, the_value)
        else:
            assert False
        return result
    else:
        return "{} : {}".format("!FORMATERROR!", raw_pseudo_file_str)


def get_list_of_open_file_descriptors(collected_data_dict, pid, args):
    """
    Get all open file descriptors as a list of strings.
    """

    pid_data = collected_data_dict["proc_data"][pid]
    real_files_strs = []
    pseudo_files_strs = []
    for fd_num_str in pid_data["open_files"].keys():
        fd_perm = pid_data["open_files"][fd_num_str]

        fd_symlink = fd_perm["symlink"]

        flags = file_mode.get_fd_flag_labels(fd_perm["file_flags"])
        file_perm     = fd_perm["file_perm"]
        file_perm_str = str(file_perm["Uid"]) + str(file_perm["Gid"]) + str(file_perm["other"])

        if ":" not in fd_symlink:
            # real files on disk

            file_identity = fd_perm["file_identity"]

            color_it = False
            for uid_type in pid_data["Uid"]:

                user_identity = {
                    "Uid":uid_type,
                    "Gid_set":pid_data["Gid"],
                }

                if not file_mode.can_access_file(user_identity, file_identity, file_perm):
                    color_it = True

            tmp_file_str = fd_symlink
            if color_it:
                tmp_file_str = get_color_str(tmp_file_str)

            if args.verbose:
                tmp_file_str = "{:>5}: ".format(fd_num_str) + tmp_file_str
            tmp_file_str = "{} (permissions: {})".format(tmp_file_str, file_perm_str)
            if flags:
                tmp_file_str = "{} (flags: {})".format(tmp_file_str, "|".join(flags))
            real_files_strs.append(tmp_file_str)

        else:
            # pseudo files: sockets, pipes, ...
            tmp_file_str = get_pseudo_file_str_rep(collected_data_dict, fd_symlink)

            if args.verbose:
                tmp_file_str = "{:>5}: ".format(fd_num_str) + tmp_file_str
            if "socket" not in fd_symlink:
                tmp_file_str = "{} (permissions: {})".format(tmp_file_str, file_perm_str)
            if flags:
                tmp_file_str = "{} (flags: {})".format(tmp_file_str, "|".join(flags))


            pseudo_files_strs.append(tmp_file_str)


    all_strs = sorted(real_files_strs) + sorted(pseudo_files_strs)

    return "\n".join(all_strs)



def get_str_rep(collected_data_dict, column, pid, args):
    """
    Get the string representation of a table element
    """

    pid_data = collected_data_dict["proc_data"][pid]
    uid_name = collected_data_dict["uid_name" ]
    gid_name = collected_data_dict["gid_name" ]

    if "Uid" not in pid_data.keys():
        return ""

    all_uids_equal = len(set(pid_data["Uid"])) == 1
    all_gids_equal = len(set(pid_data["Gid"])) == 1


    if column == "user":
        user_set = set()
        for item in set(pid_data["Uid"]):
            user_set.add(uid_name[item] if not args.verbose else "{}({})".format(uid_name[item], item))
        result = "|".join(str(x) for x in user_set)
        if not all_uids_equal:
            result.get_color_str(result)

    elif column == "groups":
        groups_set = set(pid_data["Gid"]) | set(pid_data["Groups"])
        groups_set_str = set()

        for item in groups_set:
            groups_set_str.add(gid_name[item] if not args.verbose else "{}({})".format(gid_name[item], item))
        result = "|".join(str(x) for x in groups_set_str)
        if not all_gids_equal:
            result.get_color_str(result)

    elif column == "features":
        result_list = []
        if pid_data["Seccomp"]:
            result_list.append("seccomp")
        if "root" in pid_data and pid_data["root"] != "/":
            result_list.append("chroot")

        if result_list:
            result = get_color_str("|".join(result_list))
        else:
            result = ""

    elif column[0:3] == "Cap":
        boring_cap_values = [0, 274877906943]
        all_uids_are_root = all_uids_equal and pid_data["Uid"][0] == 0
        no_uids_are_root = pid_data["Uid"].count(0) == 0

        if all_uids_are_root:
            result = ""
        elif not args.verbose and pid_data[column] in boring_cap_values:
            result = ""
        else:
            cap_trans = cap_translator.CapTranslator("cap_data.json")
            tmp_cap_list = cap_trans.get_cap_strings(pid_data[column])
            new_cap_list = []
            for tmp_cap in tmp_cap_list:
                if no_uids_are_root:
                    new_cap_list.append(get_color_str(tmp_cap))
            result = "\n".join(new_cap_list)



    elif column == "executable" or column == "parameters":
        max_len = 40
        cmdline = pid_data[column]
        cmdline_chunks = [cmdline[i:i+max_len] for i in range(0, len(cmdline), max_len)]
        result = "\n".join(cmdline_chunks)

    elif column == "open file descriptors":
        if "open_files" not in pid_data:
            result = "RACE_CONDITION"
        elif not args.fd:
            result = len(pid_data["open_files"].keys())
        else:
            result = get_list_of_open_file_descriptors(collected_data_dict, pid, args)

    elif column in pid_data:
        result = pid_data[column]
    else:
        assert False


    return result



def get_color_str(a_string):
    """
    Simple wrapper to the coloring function, unless the output is piped into
    another tool, like less or grep.
    """

    result = a_string
    if sys.stdout.isatty():
        result = termcolor.colored(a_string, "red")
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
    to_remove = set()
    for column in column_headers:
        if column != "pid":

            str_table_data[column] = {}
            for pid in all_pids:
                str_table_data[column][pid] = get_str_rep(collected_data_dict, column, pid, args)

            column_values = list(str_table_data[column].values())
            if len(set(column_values)) == 1 and column_values[0] == "":
                to_remove.add(column)

    # These values are generally uninteresting
    to_remove.add("CapAmb")
    to_remove.add("CapBnd")

    if not args.params:
        to_remove.add("parameters")


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
            exit("There is no process that has pid {} on this node.\n".format(single_pid))

        recursive = args.children
        proc_tree += recursive_proc_tree(children, single_pid, indention_count, level, recursive)



    str_table = generate_table(column_headers, proc_tree, str_table_data)


    table = terminaltables.AsciiTable(str_table)

    # Do not use any borders at all
    table.outer_border             = False
    table.inner_column_border      = False
    table.inner_heading_row_border = False

    print(table.table)



if __name__ == "__main__":
    main()
