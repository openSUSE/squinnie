#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
import codecs
import sys
import argparse
import copy
import re
import os



# Local modules
import dump_crowbar_network
import dump_node_data
import view_node_data



def main(sys_args):
    description = "The main cloud scanner, initially built for scanning a SUSE OpenStack Cloud 7 instance. A single wrapper around the functionality of all individual tools."
    parser = argparse.ArgumentParser(prog=sys_args, description=description)

    # General
    general_group = parser.add_argument_group('general arguments')

    description = "The directory all files are cached in."
    general_group.add_argument("-d", "--directory", required=True, type=str, help=description)

    description = "Print more detailed information."
    general_group.add_argument("-v", "--verbose", action="store_true", help=description)

    description = "Print information from all nodes. By default, only the crowbar node is printed."
    general_group.add_argument("-a", "--all", action="store_true", help=description)

    # Dump
    dump_group = parser.add_argument_group('scan / dump arguments')

    description = "The host on which crowbar is running."
    dump_group.add_argument("-e", "--entry", required=True, type=str, help=description)

    description = "Remove cached files after every run, forcing a re-scan on next execution."
    dump_group.add_argument("--nocache", action="store_true", help=description)

    # View
    view_group = parser.add_argument_group('view arguments')

    description = "Include kernel threads. Kernel threads are excluded by default."
    view_group.add_argument("-k", "--kthreads", action="store_true", help=description)

    description = "Only show data that belongs to the provided pid."
    view_group.add_argument("-p", "--pid", type=str, help=description)

    description = "Also print all the children of the process provided by -p/--pid."
    view_group.add_argument("--children", action="store_true", help=description)

    description = "Print the parent of the process provided by -p/--pid."
    view_group.add_argument("--parent", action="store_true", help=description)

    description = "Show capabilities as string names rather than bitstrings."
    view_group.add_argument("--cap", action="store_true", help=description)

    description = "Show detailed information on all open ordinary files."
    view_group.add_argument("--realfiles", action="store_true", help=description)

    description = "Show detailed information on all open pseudo files, such as pipes, sockets and or inodes."
    view_group.add_argument("--pseudofiles", action="store_true", help=description)


    files_produced = []

    args = parser.parse_args()
    nwconfig_filename = os.path.join(args.directory, "network.json")

    crowbar_args = argparse.Namespace()
    crowbar_args.entry = args.entry
    crowbar_args.output = nwconfig_filename
    dump_crowbar_network.dump_crowbar_to_file(crowbar_args)
    files_produced.append(nwconfig_filename)

    dump_args = argparse.Namespace()
    dump_args.input = nwconfig_filename
    dump_args.output = args.directory
    dump_args.nocache = args.nocache
    node_filenames = dump_node_data.dump(dump_args)
    files_produced += node_filenames

    view_args = argparse.Namespace()

    view_args.verbose     = args.verbose
    view_args.kthreads    = args.kthreads
    view_args.pid         = args.pid
    view_args.children    = args.children
    view_args.parent      = args.parent
    view_args.cap         = args.cap
    view_args.realfiles   = args.realfiles
    view_args.pseudofiles = args.pseudofiles

    if not args.all:
        view_args.input = os.path.join(args.directory, dump_node_data.get_filename(args.entry))
        view_node_data.view_data(view_args)
    else:
        for node_file in node_filenames:
            print("\n\nPreparing report for %s ..." % node_file)
            view_args.input = os.path.join(args.directory, node_file)
            view_node_data.view_data(view_args)

    if args.nocache:
        print("")
        print("Deleting cached files after protocol run:" % args.directory)
        for file_name in files_produced:
            file_name_path = os.path.join(args.directory, file_name)
            os.remove(file_name_path)
            print("Deleting %s" % file_name_path)
        print("")


if __name__ == "__main__":
    main(sys.argv[0])
