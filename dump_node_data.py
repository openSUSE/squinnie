#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
import os
import sys
import argparse
import json
from collections import OrderedDict
import cPickle as pickle

error_msg = "The module %s could not be found. Please use your system's package manager or pip to install it."

try:
    import execnet
except ImportError:
    print(error_msg % "execnet")
    sys.exit(1)

# local modules
import slave
import enrich_node_data



file_extension = "p" # apparently .p is commonly for pickled data



def main(sys_args):
    description = "Dump one file per node configured as network."
    parser = argparse.ArgumentParser(prog=sys_args, description=description)

    description = "The input file your network is described with."
    parser.add_argument("-i", "--input", required=True, type=str, help=description)

    description = "The output path you want your data files to be dumped to."
    parser.add_argument("-o", "--output", required=True, type=str, help=description)

    description = "Force overwriting files, even if cached files are already present."
    parser.add_argument("--nocache", action="store_true", help=description)

    args = parser.parse_args()

    if not os.path.exists(args.input):
        exit("The file given by the -i/--input parameter does not exist.\n")
    elif not os.path.isfile(args.input):
        exit("The -i/--input parameter must be a file.\n")

    if not os.path.exists(args.output):
        exit("The directory given by the -o/--output parameter does not exist.\n")
    elif not os.path.isdir(args.output):
        exit("The -o/--output parameter must be a directory.\n")

    dump(args)



def files_already_exist(directory_path, filenames):
    result = True
    for fname in filenames:
        if not os.path.isfile( os.path.join(directory_path, fname) ):
            result = False
    return result



def dump(args):
    directory_path = args.output
    tree_dict_str = read_network_config(args.input)

    node_list = []
    tree_dict_to_list(node_list, tree_dict_str)
    node_list_filenames = [get_filename(item) for item in node_list]


    if not args.nocache and files_already_exist(directory_path, node_list_filenames):
        print("Skip another scan because a suitable cache was found.")
        print("You can force rebuilding the cache from scratch using --nocache.")
        print("")
    else:

        (datastructure, node_list) = receive_data(tree_dict_str)
        write_data(directory_path, datastructure, node_list)

    return node_list_filenames



def execnet_recursive_setup(group, parent, tree_dict_str):

    # In case the current node has children
    if type(tree_dict_str) is OrderedDict:
        for self_node, children in tree_dict_str.items():
            group.makegateway(get_gateway_option_string(parent, self_node))

            execnet_recursive_setup(group, self_node, children)

    # In case the current node is a leaf in the tree
    elif type(tree_dict_str) is list:
        for self_node in tree_dict_str:
            group.makegateway(get_gateway_option_string(parent, self_node))



def print_recursively(tree_dict_str, level):

    # In case the current node has children
    if type(tree_dict_str) is OrderedDict:
        for self_node, children in tree_dict_str.items():
            print("+---"*level + self_node)

            print_recursively(children, level+1)

    # In case the current node is a leaf in the tree
    elif type(tree_dict_str) is list:
        for self_node in tree_dict_str:
            print("+---"*level + self_node)



def tree_dict_to_list(working_set, tree_dict_str):

    # In case the current node has children
    if type(tree_dict_str) is OrderedDict:
        for self_node, children in tree_dict_str.items():
            working_set.append(self_node)

            tree_dict_to_list(working_set, children)

    # In case the current node is a leaf in the tree
    elif type(tree_dict_str) is list:
        for self_node in tree_dict_str:
            working_set.append(self_node)



def get_gateway_option_string(execnet_via, execnet_id):
    data = {
        "ssh"   :"root@%s"  % execnet_id,
        "id"    : "%s"      % execnet_id,
        "python":"python%d" % sys.version_info.major,
    }

    if execnet_via:
        data["via"] = execnet_via

    data_str = ["%s=%s" % (key, value) for key, value in data.items()]

    return "//".join(data_str)



def receive_data(tree_dict_str):
    group = execnet.Group()
    execnet_recursive_setup(group, None, tree_dict_str)

    node_list = []
    tree_dict_to_list(node_list, tree_dict_str)

    datastructure = {}
    for node_str in node_list:
        print("Receiving data from %s" % node_str)
        datastructure[node_str] = group[node_str].remote_exec(slave).receive()
    print("")

    return (datastructure, node_list)



def read_network_config(file_name):
    with open(file_name, "r") as fi:
        tree_dict_str = json.load(fi, object_pairs_hook=OrderedDict)

    assert len(tree_dict_str.keys()) == 1

    return tree_dict_str



def get_filename(node_str):
    return "%s.%s" % (node_str.replace(".", "-"), file_extension)



def write_data(file_path, datastructure, node_list):
    for node_str in node_list:
        file_name = get_filename(node_str)
        file_path_name = os.path.join(file_path, file_name)
        print("Saving data to %s" % file_path_name)


        with open(file_path_name, "w") as fi:
            pickle.dump({node_str:datastructure[node_str]}, fi)

        enrich_node_data.enrich_if_necessary(file_path_name)

    print("")



if __name__ == "__main__":
    main(sys.argv[0])
