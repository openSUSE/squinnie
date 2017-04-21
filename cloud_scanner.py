#!/usr/bin/env python2

# Standard library modules.
import sys
import argparse

# External dependencies.
import master

def main():
    desc = "Scan a SUSE OpenStack Cloud 7 network instance."
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=desc)

    a_desc = "Scan all nodes. Only the entry node is scanned by default."
    parser.add_argument("-a", "--all", action="store_true", help=a_desc)

    a_desc = "Include kernel threads. Kernel threads are excluded by default."
    parser.add_argument("-k", "--kthreads", action="store_true", help=a_desc)

    requiredNamed = parser.add_argument_group('required named arguments')
    entry_desc = "The host on which crowbar is running."
    requiredNamed.add_argument('-e', '--entry', type=str, help=entry_desc, required=True)

    args = parser.parse_args()

    if not args.entry:
        exit("Please provide an entry node.")

    if not args.all:
        master.scan_entry_node(args.entry, args.kthreads)
    else:
        master.scan_all(args.entry, args.kthreads)

if __name__ == "__main__":
    main()
