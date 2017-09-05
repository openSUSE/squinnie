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
import argparse
import sys
import os

# local modules
import sscanner.helper as helper
pickle = helper.importPickle()


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

    pids = collected_data_dict["proc_data"].keys()
    parents = collected_data_dict["parents"]
    collected_data_dict["children"] = parents_to_children(pids, parents)

    with open(file_name, "wb") as fi:
        pickle.dump({node_str:collected_data_dict}, fi, protocol = 2)



def read_data(file_name):

    if os.path.exists(file_name):
        with open(file_name, "r") as my_file:
            datastructure = pickle.load(my_file)
    else:
        exit("The file {} does not exist. Exiting.".format(file_name))


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
