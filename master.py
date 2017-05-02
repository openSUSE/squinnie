"""
This script is not intended to be run manually, but via the clsc main script.
"""

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
from collections import OrderedDict
import sys
import codecs
import copy

# PyPy modules
import execnet
import termcolor
import yaml

# External dependencies
import slave as collector

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

        if args.node:
            nodes_to_print = [args.node]
        else:
            nodes_to_print = datastructure.keys()

        for node_str in nodes_to_print:
            print("")
            try:
                collected_data_dict = datastructure[node_str]
            except:
                exit("Sorry, but there seems to be no node with the name '%s'.\nExiting now.\n" % node_str)

            print("Accessing: %s" % node_str)
            print("There are %d processes running on this host." % len(collected_data_dict["status"].keys()))
            print("")
            print_process_tree(collected_data_dict, args)



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



def build_data(node_str, group, args):
    print("Collecting data from %s" % node_str)
    slave  = group.makegateway("via=master//python=python%d//ssh=root@%s" % (sys.version_info.major, node_str))
    collected_data_dict = slave.remote_exec(collector).receive()

    pids = collected_data_dict["status"].keys()
    parents = collected_data_dict["parents"]
    collected_data_dict["children"] = parents_to_children(pids, parents)

    name_uidgid = collected_data_dict["name_uidgid"]
    collected_data_dict["uid_name"] = username_to_uid(name_uidgid)
    collected_data_dict["gid_name"] = username_to_gid(name_uidgid)

    return collected_data_dict



def username_to_uid(usernames):
    return username_to_xid(usernames, "Uid")



def username_to_gid(usernames):
    return username_to_xid(usernames, "Gid")



def username_to_xid(usernames, mode):
    if mode == "Uid":
        mode_index = 0
    elif mode == "Gid":
        mode_index = 1
    else:
        exit("Error: Not implemented.")

    xid_data = {}
    for uname in usernames:
        current_xid = usernames[uname][mode_index]
        xid_data.setdefault(current_xid,[]).append(uname)

    return xid_data



def parents_to_children(pids, parents):
    children = {}
    for p in pids:
        if p in parents.keys():
            the_parent = parents[p]
            if not the_parent in children.keys():
                children[the_parent] = []
            children[the_parent].append(p)
        else:
            continue

    return children



def print_process_tree(collected_data_dict, args):

    column_headers = [
        "process tree",
        "username",
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

    uninteresting_values = {
        "Seccomp":[False],
        "CapInh" :[0],
        "CapAmb" :[0],
        "CapPrm" :[0, 274877906943],
        "CapEff" :[0, 274877906943],
        "CapBnd" :[0, 274877906943],
    }


    if not args.verbose:
        data_table = blank_out_values(data_table, uninteresting_values)
        data_table = remove_blank_columns(data_table)

    str_table = convert_table_compact(data_table)

    str_table = convert_table_spaces(str_table)

    str_table = convert_table_color(data_table, str_table)

    print_table(str_table)




def get_unformatted_table(column_headers, collected_data_dict, pid, indention_count, level):
    """
    Recursive function
    """

    children_data = collected_data_dict["children"]
    status_data   = collected_data_dict["status"]
    open_file_pointers = collected_data_dict["open_file_pointers"]

    name_uidgid = collected_data_dict["name_uidgid"]
    gid_name = collected_data_dict["gid_name"]

    indenter = indention_count * " "

    self_row = []
    for column_name in column_headers:
        result_str = ""
        column_data = ""
        if column_name in status_data[pid].keys():
            column_data = status_data[pid][column_name]
            result_str = column_data

        elif column_name == "process tree":
            result_str = indenter * level + "+---" + str(pid)

        elif column_name == "username":
            unames = []
            for uid_type in status_data[pid]["Uid"]:
                for name in collected_data_dict["uid_name"][uid_type]:
                    unames.append(name)
                unames = list(set(unames))
            result_str = "|".join(unames)
        self_row.append(result_str)

    # self_row is now complete !

    children_rows = []

    if pid in children_data.keys(): # if current pid has children
        for child_pid in sorted(children_data[pid]):
            children_rows += get_unformatted_table(column_headers, collected_data_dict, child_pid, indention_count, level+1)
    return [self_row] + children_rows



# http://stackoverflow.com/questions/3787908/python-determine-if-all-items-of-a-list-are-the-same-item
def all_same(items):
    return all(x == items[0] for x in items)



def blank_out_values(data_table, uninteresting_values):
    """
    data_table: a list of lists, e.g. [ [], [], [], [], ... ]. Each list
    inside represents a row. The first row is the header row, giving each
    column its names.

    uninteresting_values: a dict like {"column_name" : ["uninteresting1", ...]}
    """

    result_table = copy.deepcopy(data_table)

    for u_column, u_cond_list in uninteresting_values.items():
        assert u_column in result_table[0]

        number_of_columns = len(result_table[0])
        u_column_index = result_table[0].index(u_column)

        replace_with_empty_str = True

        for row in result_table[1:]: # Skip header row
            if row[u_column_index] in u_cond_list:
                row[u_column_index] = ""

    return result_table



def remove_blank_columns(data_table):

    number_of_columns = len(data_table[0])

    # Collect a list of all columns we want to remove by saving their indices
    columns_to_remove = []
    for column_index in range(number_of_columns):

        remove_this_row = True
        for row in data_table[1:]:
            if row[column_index] != "":
                remove_this_row = False

        if remove_this_row:
            columns_to_remove.append(column_index)

    # Now remove the collected columns
    while columns_to_remove:
        column_index = columns_to_remove.pop()

        for row in data_table:
            del row[column_index]

    return data_table




def convert_table_compact(data_table):

    columns = [
        "Uid",
        "Gid",
        "cmdline",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
    ]



    indices = {}
    for c in columns:
        indices[c] = get_index(data_table, c)

    used_columns = [column for column,index in indices.items() if index != None]
    used_caps = [item for item in used_columns if item[0:3] == "Cap"]

    str_table = copy.deepcopy(data_table)

    for (data_row, str_row) in zip(data_table[1:], str_table[1:]):

        # If all uids are equal, only show one for compact view
        if all_same(data_row[indices["Uid"]]):
            str_row[indices["Uid"]] = data_row[indices["Uid"]][0]

        if all_same(data_row[indices["Gid"]]):
            str_row[indices["Gid"]] = data_row[indices["Gid"]][0]

        str_row[indices["cmdline"]] = data_row[indices["cmdline"]]
        cmdline_len = 60
        if len(data_row[indices["cmdline"]]) > cmdline_len:
            str_row[indices["cmdline"]] = str_row[indices["cmdline"]][:cmdline_len - 3] + "..."

        for c in used_caps:
            if str_row[indices[c]] != "":
                str_row[indices[c]] = "%016x" % data_row[indices[c]]

    return str_table



def convert_table_spaces(str_table):
    number_of_columns = len(str_table[0])
    max_data = get_max_lengths(str_table)

    result_table = []
    for row in str_table:
        new_row = []
        for i in range(number_of_columns):
            new_str = str(row[i]).ljust(max_data[i])
            new_row.append(new_str)
        result_table.append(new_row)

    return result_table



def get_max_lengths(data_table):
    number_of_columns = len(data_table[0])
    result = []
    for i in range(number_of_columns):
        maxchars = 0
        for row in data_table:
            chars_count = len(str(row[i]))
            if chars_count > maxchars:
                maxchars = chars_count
        result.append(maxchars)

    return result



def get_index(data_table, column):
    result = None
    if column in data_table[0]:
        result = data_table[0].index(column)
    return result



def convert_table_color(data_table, str_table):
    """
    Note: The information in data_table and str_table is identical,
    except that the values inside str_table are padded with spaces.

    This function will color the data in str_table based on the data values
    in data_table.
    """

    columns = [
    "Uid",
    "Gid",
    "Seccomp",
    "CapInh",
    "CapAmb",
    "CapPrm",
    "CapEff",
    "CapBnd",
    ]

    indices = {}
    for c in columns:
        indices[c] = get_index(data_table, c)

    used_columns = [column for column,index in indices.items() if index != None]

    used_caps = [item for item in used_columns if item[0:3] == "Cap"]

    for (data_row, str_row) in zip(data_table[1:], str_table[1:]): # Use table with padded values here

        # processes running as non-root and non-suid, but that have certain capabilities set
        if indices["Uid"] and indices["Gid"]:
            if 0 == ( data_row[indices["Uid"]].count(0) + data_row[indices["Gid"]].count(0) ):

                for c in used_caps:
                    if data_row[indices[c]] != 0:
                        str_row[indices[c]] = termcolor.colored(str_row[indices[c]], "red")
                        # print("CALL: color_it complex")

        # processes whose real/effective uid/gid are different
        if indices["Uid"] and not all_same(data_row[indices["Uid"]]):
            str_row[indices["Uid"]] = termcolor.colored(str_row[indices["Uid"]], "red")
            # print("CALL: color_it uid")
        if indices["Gid"] and not all_same(data_row[indices["Gid"]]):
            str_row[indices["Gid"]] = termcolor.colored(str_row[indices["Gid"]], "red")
            # print("CALL: color_it gid")

        # processes having seccomp activated
        if indices["Seccomp"] and data_row[indices["Seccomp"]] == True:
            str_row[indices["Seccomp"]] = termcolor.colored(str_row[indices["Seccomp"]], "red")
            # print("CALL: color_it seccomp")

    return str_table

def print_table(data_table):
    for row in data_table:
        for item in row:
            print(item, end=" ")
        print("")
