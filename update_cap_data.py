#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
from collections import OrderedDict
import re
import json
import argparse
import sys
import os



def main(sys_args):
    description = "Update the capability data cache generated from capability.h"
    parser = argparse.ArgumentParser(prog=sys_args, description=description)

    description = "The capability.h file. If not provided, /usr/include/linux/capability.h will be used."
    parser.add_argument("-i", "--input", type=str, help=description)

    description = "The output file for capability configuration in JSON format."
    parser.add_argument("-o", "--output", type=str, help=description)

    args = parser.parse_args()



    if args.input:
        file_name = args.input
    else:
        file_name = "/usr/include/linux/capability.h"


    if os.path.isfile(file_name):
        try:
            with open(file_name, "r") as fi:
                file_data = fi.read()
        except EnvironmentError:
            exit("The file {} exists, but cannot be opened.".format(file_name))
    else:
        exit("The file {} does not exist.".format(file_name))

    assert file_data

    regex = re.compile("#define (CAP_[A-Z_]+)\s+(\d+)", re.MULTILINE)

    cap_data = OrderedDict()
    for m in re.finditer(regex, file_data):
        cap_int  = int(m.group(2))
        cap_name = str(m.group(1))
        cap_data[cap_name] = cap_int

    if args.output:
        file_path_name = args.output
    else:
        file_path_name = os.path.join( os.path.dirname(__file__), "cap_data.json" )

    with open(file_path_name, "w") as fi:
        json.dump(cap_data, fi, indent=4, sort_keys=True)
        print("Wrote capability data to {}\n".format(file_path_name))



if __name__ == "__main__":
    main(sys.argv[0])
