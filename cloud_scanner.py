#!/usr/bin/env python2

# Standard library modules.
import sys
import argparse

# External dependencies.
import master

def main():
    description = "Scan a SUSE OpenStack Cloud 7 network instance."
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)

    description = "Scan all nodes. Only the entry node is scanned by default. This flag has no effect if -i/--input is set."
    parser.add_argument("-a", "--all", action="store_true", help=description)

    description = "Include kernel threads. Kernel threads are excluded by default."
    parser.add_argument("-k", "--kthreads", action="store_true", help=description)

    description = "The output file you want your data to be dumped to."
    parser.add_argument("-o", "--output", type=str, help=description)


    group = parser.add_mutually_exclusive_group(required=True)
    description = "The input file to view your dumped data from."
    group.add_argument("-i", "--input", type=str, help=description)
    description = "The host on which crowbar is running."
    group.add_argument('-e', '--entry', type=str, help=description)

    args = parser.parse_args()

    if args.output and args.input:
        exit("You cannot combine -i/--input and -o/--output.")

    master.produce_global_datastructure(args)


if __name__ == "__main__":
    main()
