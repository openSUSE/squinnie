#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
import sys
import argparse
import copy
import re
import os



# Local modules
import dump_crowbar_network
import dump_node_data
import view_node_data



def main():
    description = "The main cloud scanner, initially built for scanning a SUSE OpenStack Cloud 7 instance. A single wrapper around the functionality of all individual tools."
    parser = argparse.ArgumentParser(description=description)

    # General
    general_group = parser.add_argument_group('general arguments')

    description = "The directory all files are cached in. If no value is given here, /tmp/cloud_scanner/ will be used to save files during the execution of the script and then deleted at the end."
    general_group.add_argument("-d", "--directory", type=str, help=description)

    description = "Print more detailed information."
    general_group.add_argument("-v", "--verbose", action="store_true", help=description)

    # description = "List all nodes in the network."
    # general_group.add_argument("-l", "--list", action="store_true", help=description)

    description = "Print information from all nodes. By default, only the crowbar node is printed."
    general_group.add_argument("-a", "--all", action="store_true", help=description)

    # Dump
    dump_group = parser.add_argument_group('scan / dump arguments')

    description = "The host on which crowbar is running."
    dump_group.add_argument("-e", "--entry", type=str, help=description)

    description = "Remove cached files after every run, forcing a re-scan on next execution."
    dump_group.add_argument("--nocache", action="store_true", help=description)

    # View
    view_group = parser.add_argument_group('view arguments')

    description = "Hide table borders completely. Useful for tools like less and grep."
    view_group.add_argument("--hideborders", action="store_true", help=description)

    description = "Show parameters from the executable cmdline variable."
    view_group.add_argument("--params", action="store_true", help=description)

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

    description = "Show all open file descriptors for every process."
    view_group.add_argument("--fd", action="store_true", help=description)

    description = "Show only the open file descriptors in a dedicated view and nothing else."
    view_group.add_argument("--onlyfd", action="store_true", help=description)

    # Allow setting args using an environment variable
    try:
        extra_args = os.environ["CLOUD_SCANNER"]
    except KeyError:
        extra_args = ""
    args = parser.parse_args(sys.argv[1:] + extra_args.split())

    finally_remove_dir = False
    if not args.directory:
        args.directory = "/tmp/cloud_scanner/"
        if not os.path.isdir(args.directory):
            os.mkdir(args.directory)
        finally_remove_dir = True

    if not os.path.isdir(args.directory):
        exit("The directory {} does not exist. Please create it using mkdir.".format(args.directory))

    files_produced = []
    nwconfig_file_name = "network.json"
    nwconfig_file_name_path = os.path.join(args.directory, nwconfig_file_name)

    # dump_crowbar_network arguments
    crowbar_args = argparse.Namespace()
    crowbar_args.entry = args.entry
    crowbar_args.nocache = args.nocache
    crowbar_args.output = nwconfig_file_name_path

    entry_node = dump_crowbar_network.dump_crowbar_to_file(crowbar_args)
    files_produced.append(nwconfig_file_name)

    # if args.list:
    #     print("The following nodes are in the network:")
    #     for node_file in node_filenames:
    #         print("- {}".format(node_file))
    #     print("")
    #     exit()

    # dump_node_data arguments
    dump_args = argparse.Namespace()
    dump_args.input = nwconfig_file_name_path
    dump_args.output = args.directory
    dump_args.nocache = args.nocache

    node_filenames = dump_node_data.dump(dump_args)
    files_produced += node_filenames

    # view_node_data arguments
    view_args = argparse.Namespace()
    view_args.verbose     = args.verbose
    view_args.hideborders = args.hideborders
    view_args.params      = args.params
    view_args.kthreads    = args.kthreads
    view_args.pid         = args.pid
    view_args.children    = args.children
    view_args.parent      = args.parent
    view_args.cap         = args.cap
    view_args.fd          = args.fd
    view_args.onlyfd      = args.onlyfd



    if not args.all:
        print("\n\nPreparing report for {} ...".format(entry_node))
        view_args.input = os.path.join(args.directory, dump_node_data.get_filename(entry_node))
        view_node_data.view_data(view_args)
    else:
        for node_file in node_filenames:
            print("\n\nPreparing report for {} ...".format(node_file))
            view_args.input = os.path.join(args.directory, node_file)
            view_node_data.view_data(view_args)


    if args.verbose and finally_remove_dir:
        print("")
        print("Deleting cached files after protocol run:")
        for file_name in files_produced:
            file_name_path = os.path.join(args.directory, file_name)
            os.remove(file_name_path)
            print("Deleting {}".format(file_name_path))
        os.rmdir(args.directory)
        print("Deleting {}".format(args.directory))
        print("")


if __name__ == "__main__":
    main()
