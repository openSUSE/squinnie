#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
import codecs
import sys
import argparse
import json
from collections import OrderedDict

# PyPy modules
import execnet
import yaml

# local modules
import slave



def main():
    description = "Dump one file per node configured as network."
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)

    description = "The input file your network is described with."
    parser.add_argument("-i", "--input", required=True, type=str, help=description)

    description = "The output path you want your data files to be dumped to."
    parser.add_argument("-o", "--output", required=True, type=str, help=description)

    args = parser.parse_args()

    tree_dict_str = read_network_config(args.input)

    (datastructure, node_list) = receive_data(tree_dict_str)

    write_data(datastructure, node_list, args.output)



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
    with codecs.open(file_name, "r", encoding="utf-8") as fi:
        tree_dict_str = json.load(fi, object_pairs_hook=OrderedDict)

    assert len(tree_dict_str.keys()) == 1

    return tree_dict_str



def write_data(datastructure, node_list, file_path):
    for node_str in node_list:
        file_name = "%s.yml" % node_str.replace(".", "-")
        file_path_name = file_path + file_name
        print("Saving data to %s" % file_path_name)

        with codecs.open(file_path_name, "w", encoding="utf-8") as fi:
            yaml.dump({node_str:datastructure[node_str]}, fi, default_flow_style=False)
    print("")



if __name__ == "__main__":
    main()
