#!/usr/bin/env python2

# Standard library modules.
import sys
import argparse
import itertools

# External dependencies.
import master

def main():
    description = "Scan a SUSE OpenStack Cloud 7 network instance."
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)

    # Options to choose whether to scan or not
    group = parser.add_mutually_exclusive_group(required=True)
    description = "The input file to view your dumped data from."
    group.add_argument("-i", "--input", type=str, help=description)
    description = "The host on which crowbar is running."
    group.add_argument("-e", "--entry", type=str, help=description)

    description = "The output file you want your data to be dumped to."
    parser.add_argument("-o", "--output", type=str, help=description)

    # Scan options
    description = "Scan all nodes. Only the entry node is scanned by default. This flag has no effect if -i/--input is set."
    parser.add_argument("-a", "--all", action="store_true", help=description)

    # View options
    description = "Include kernel threads. Kernel threads are excluded by default."
    parser.add_argument("-k", "--kthreads", action="store_true", help=description)

    description = "List all hosts known by crowbar."
    parser.add_argument("-l", "--list", action="store_true", help=description)

    description = "Print more useful information."
    parser.add_argument("-v", "--verbose", action="store_true", help=description)

    description = "Filter so that only data from the given node is printed."
    parser.add_argument("-n", "--node", type=str, help=description)

    description = "Filter so that only data from the given pid is printed."
    parser.add_argument("-p", "--pid", type=str, help=description)

    description = "Also print all the children of the process given by -p/--pid."
    parser.add_argument("--children", action="store_true", help=description)

    description = "Print the parent of the process given by -p/--pid and all its children."
    parser.add_argument("--parent", action="store_true", help=description)



    args = parser.parse_args()

    if not args.node and args.pid:
        exit("To use -p/--pid, you have to use -n/--node.")

    if args.output and args.input:
        exit("You cannot combine -i/--input and -o/--output.")

    master.produce_global_datastructure(args)


if __name__ == "__main__":
    main()
