#!/usr/bin/env python2

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
import codecs
import sys

# PyPy modules
import yaml

def nth_bit_set(val, n):
    return 0 != val & (1 << n)

def get_cap_strings(cap_data, cap_num):
    result = []

    for cap_name, index in cap_data.items():
        if nth_bit_set(cap_num, index):
            result.append(cap_name)

    return result

def get_cap_data(file_name):
    with codecs.open(file_name, "r", encoding="utf-8") as fi:
        return yaml.load(fi)

def main():
    if len(sys.argv) < 2:
        exit("You have to provide a bitstring.\n")

    file_name = "data/cap_data.json"
    cap_data = get_cap_data(file_name)
    print("\nThe given bitstring maps to the following capabilities:\n")
    cap_num = int(sys.argv[1], 16)
    for cap in get_cap_strings(cap_data, cap_num):
        print("- %s" % cap)
    print("")

if __name__ == "__main__":
    main()
