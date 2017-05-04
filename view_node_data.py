#!/usr/bin/env python2

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
import codecs
import sys
import argparse
import copy

# PyPy modules
import yaml
from terminaltables import AsciiTable



def main():
    description = "View a data dump of any single node."
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)

    description = "The input file to view your dumped data from."
    parser.add_argument("-i", "--input", required=True, type=str, help=description)

    description = "Include kernel threads. Kernel threads are excluded by default."
    parser.add_argument("-k", "--kthreads", action="store_true", help=description)

    description = "Filter so that only data from the given pid is printed."
    parser.add_argument("-p", "--pid", type=str, help=description)

    description = "Print more detailed information."
    parser.add_argument("-v", "--verbose", action="store_true", help=description)

    description = "Also print all the children of the process given by -p/--pid."
    parser.add_argument("--children", action="store_true", help=description)

    description = "Print the parent of the process given by -p/--pid."
    parser.add_argument("--parent", action="store_true", help=description)

    args = parser.parse_args()

    view_data(args)



def view_data(args):

    with codecs.open(args.input, "r", encoding="utf-8") as fi:
        datastructure = yaml.load(fi)
    assert len(datastructure.keys()) == 1

    node_str = datastructure.keys()[0]

    collected_data_dict = datastructure[node_str]

    print("There are %d processes running on this host." % len(collected_data_dict["status"].keys()))
    print("")
    print_process_tree(collected_data_dict, args)



def print_process_tree(collected_data_dict, args):

    column_headers = [
        "pid",
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

    # Standard behaviour, print information for all pids
    if not args.pid:
        data_table += get_unformatted_table(column_headers, collected_data_dict, 1, indention_count, level, True)
        if args.kthreads:
            data_table += get_unformatted_table(column_headers, collected_data_dict, 2, indention_count, level, True)

    # In case user wants to examine a process
    else:
        single_pid = int(args.pid)
        if args.parent:
            single_pid = collected_data_dict["parents"][single_pid]

        if not single_pid in collected_data_dict["status"]:
            exit("There is no process that has pid %d on this node.\n" % single_pid)

        recursive = args.children
        data_table += get_unformatted_table(column_headers, collected_data_dict, single_pid, indention_count, level, recursive)


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
        data_table = remove_columns(data_table, ["CapAmb", "CapBnd"])

    str_table = convert_table_compact(data_table)

    # str_table = convert_table_spaces(str_table)

    # str_table = convert_table_color(data_table, str_table)

    # cap_table = get_cap_table(data_table)
    # cap_table = {}

    # print_table(str_table, cap_table)

    table = AsciiTable(str_table)
    table.inner_column_border = False
    table.outer_border = False
    print(table.table)



def remove_columns(data_table, columns_to_remove):
    number_of_columns = len(data_table[0])

    indices = {}
    for c in columns_to_remove:
        indices[c] = get_index(data_table, c)

    # Now remove the collected columns
    while columns_to_remove:
        column = columns_to_remove.pop()
        if column not in data_table[0]:
            continue

        column_index = indices[column]

        # import pdb; pdb.set_trace()

        for row in data_table:
            del row[column_index]

    return data_table



def get_unformatted_table(column_headers, collected_data_dict, pid, indention_count, level, recursive):
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
        if column_name == "pid":
            # result_str = pid
            result_str = indenter * level + "+---" + str(pid)
        elif column_name in status_data[pid].keys():
            result_str = status_data[pid][column_name]

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
    # if current pid has children and unless the user does not explicitly want them printed
    if recursive and pid in children_data.keys():
        for child_pid in sorted(children_data[pid]):
            children_rows += get_unformatted_table(column_headers, collected_data_dict, child_pid, indention_count, level+1, recursive)

    return [self_row] + children_rows



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
        cmdline_len = 35
        if len(data_row[indices["cmdline"]]) > cmdline_len:
            str_row[indices["cmdline"]] = str_row[indices["cmdline"]][:cmdline_len - 3] + "..."

        for c in used_caps:
            if str_row[indices[c]] != "":
                str_row[indices[c]] = "%016x" % data_row[indices[c]]

    return str_table



def get_index(data_table, column):
    result = None
    if column in data_table[0]:
        result = data_table[0].index(column)
    return result



# http://stackoverflow.com/questions/3787908/python-determine-if-all-items-of-a-list-are-the-same-item
def all_same(items):
    return all(x == items[0] for x in items)



if __name__ == "__main__":
    main()
