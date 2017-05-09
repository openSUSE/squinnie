#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
import codecs
import sys
import argparse

# PyPy modules
import yaml



def main():
    description = "View a data dump of any single node."
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)

    description = "The scanned data dump from the file that will get modified."
    parser.add_argument("-i", "--input", required=True, type=str, help=description)

    args = parser.parse_args()

    enrich_if_necessary(node_str, collected_data_dict, args.input)



def enrich_if_necessary(file_name):

    (node_str, collected_data_dict) = read_data(file_name)

    if is_enriched(collected_data_dict):
        return

    pids = collected_data_dict["status"].keys()
    parents = collected_data_dict["parents"]
    collected_data_dict["children"] = parents_to_children(pids, parents)

    name_uidgid = collected_data_dict["name_uidgid"]
    collected_data_dict["uid_name"] = username_to_uid(name_uidgid)
    collected_data_dict["gid_name"] = username_to_gid(name_uidgid)

    with codecs.open(file_name, "w", encoding="utf-8") as fi:
        yaml.dump({node_str:collected_data_dict}, fi, default_flow_style=False)



def read_data(file_name):
    with codecs.open(file_name, "r", encoding="utf-8") as fi:
        datastructure = yaml.load(fi)
    assert len(datastructure.keys()) == 1

    node_str = datastructure.keys()[0]
    collected_data_dict = datastructure[node_str]

    return (node_str, collected_data_dict)



def is_enriched(collected_data_dict):
    enriched_keys = ["children","uid_name","gid_name"]

    for key in enriched_keys:
        if key not in collected_data_dict.keys():
            return False

    return True



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



if __name__ == "__main__":
    main()
