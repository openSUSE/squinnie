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
import slave



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

    description = "When using a mode that scans multiple hosts, print information from all nodes. By default, only the entry node is printed. This has no effect if the local mode is used."
    general_group.add_argument("-a", "--all", action="store_true", help=description)

    # Dump
    dump_group = parser.add_argument_group('scan / dump arguments')

    description = "The mode the scanner should be operating under. Currenly supported are local and susecloud."
    dump_group.add_argument("-m", "--mode", type=str, help=description)

    description = "The host on which crowbar is running. Only valid if using the susecloud mode."
    dump_group.add_argument("-e", "--entry", type=str, help=description)

    description = "Remove cached files after every run, forcing a re-scan on next execution."
    dump_group.add_argument("--nocache", action="store_true", help=description)

    # View
    view_group = parser.add_argument_group('view arguments')

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

    description = "Show all open file descriptors for every process."
    view_group.add_argument("--fd", action="store_true", help=description)

    description = "Show only the open file descriptors in a dedicated view and nothing else."
    view_group.add_argument("--onlyfd", action="store_true", help=description)

    description = "View alle files on the file system, including their permissions."
    view_group.add_argument("--filesystem", action="store_true", help=description)

    args = parser.parse_args(sys.argv[1:])

    if not args.mode:
        args.mode = "local"
        eprint("No mode was given, so localhost is scanned by default.")

    if args.mode == "local" and os.geteuid() != 0:
        eprint("When scanning the local machine, root privileges are required to run this script.")
        eprint("Please try again, this time using 'sudo'. Exiting.")
        sys.exit(1)

    finally_remove_dir = False
    if not args.directory:
        args.directory = "/tmp/cloud_scanner_{}/".format(os.getpid())
        if not os.path.isdir(args.directory):
            os.mkdir(args.directory)
        finally_remove_dir = True
        print("No directory supplied. Cached data will be automatically deleted at the end of this run.")
        print("")

    if not os.path.isdir(args.directory):
        exit("The directory {} does not exist. Please create it using mkdir.".format(args.directory))

    files_produced = []
    nwconfig_file_name = "network.json"
    nwconfig_file_name_path = os.path.join(args.directory, nwconfig_file_name)

    if args.mode == "local":
        pass # Local, don't use crowbar...
    elif args.mode == "susecloud":
        # dump_crowbar_network arguments
        crowbar_args = argparse.Namespace()
        crowbar_args.entry = args.entry
        crowbar_args.nocache = args.nocache
        crowbar_args.output = nwconfig_file_name_path

        entry_node = dump_crowbar_network.dump_crowbar_to_file(crowbar_args)
        files_produced.append(nwconfig_file_name)

    if args.mode == "local":
        # dump_node_data arguments
        dump_args = argparse.Namespace()
        dump_args.input = "local"
        dump_args.output = args.directory
        dump_args.nocache = args.nocache

        node_filenames = dump_node_data.dump_local(dump_args)
        files_produced += node_filenames

    elif args.mode == "susecloud":
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
    view_args.params      = args.params
    view_args.kthreads    = args.kthreads
    view_args.pid         = args.pid
    view_args.children    = args.children
    view_args.parent      = args.parent
    view_args.fd          = args.fd
    view_args.onlyfd      = args.onlyfd
    view_args.filesystem  = args.filesystem

    if args.mode == "local":
        args.all = True

    if not args.all:
        eprint("\n\nPreparing report for {} ...".format(entry_node))
        view_args.input = os.path.join(args.directory, dump_node_data.get_filename(entry_node))
        view_node_data.view_data(view_args)
    else:
        for node_file in node_filenames:
            eprint("\n\nPreparing report for {} ...".format(node_file))
            view_args.input = os.path.join(args.directory, node_file)
            view_node_data.view_data(view_args)


    if finally_remove_dir:
        if args.verbose:
            eprint("")
            eprint("Deleting cached files after protocol run:")
        for file_name in files_produced:
            file_name_path = os.path.join(args.directory, file_name)
            os.remove(file_name_path)
            if args.verbose:
                eprint("Deleting {}".format(file_name_path))
        os.rmdir(args.directory)
        if args.verbose:
            eprint("Deleting {}".format(args.directory))
            eprint("")



def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)



if __name__ == "__main__":
    main()
