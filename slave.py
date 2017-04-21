"""
This script is intended to be run on the client remotely via execnet.
It can however also be called as a standalone script for testing purposes.

Unfortunately, to send a module via execnet, it has to be self-contained. This
results in this file being very long, as it is not possible to use external
imports, unless execnet_importhook gets ported to python2.
"""

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
import os
import re
from collections import OrderedDict
import json
import copy

cap_lambda     = lambda a: int(a, base = 16)
gid_uid_lambda = lambda a: tuple(int(i) for i in a.split("\t"))
groups_lambda  = lambda a: [int(i) for i in a.split()]
seccomp_lambda = lambda a: a == 1

interesting_status_fields = {
    "CapInh" : cap_lambda,
    "CapPrm" : cap_lambda,
    "CapEff" : cap_lambda,
    "CapBnd" : cap_lambda,
    "CapAmb" : cap_lambda,
    "Gid"    : gid_uid_lambda,
    "Groups" : groups_lambda,
    "Seccomp": seccomp_lambda,
    "Uid"    : gid_uid_lambda,
}

def get_corresponding_regex(field_to_search_for):
    return "^%s:\s(.*)$" % (field_to_search_for)


# Send one big dictionary at the end
result = {}

pids = []
# traverse root directory, and list directories as dirs and files as files
for entry in os.listdir("/proc"):
    fp = os.path.join( "/proc", entry )
    if not os.path.isdir(fp):
        continue
    try:
        pid = int(entry)
    except ValueError:
        continue
    pids.append(pid)

parents = {}
status = {}
for p in copy.copy(pids):
    try:
        with open("/proc/%d/status" % (p), "r") as fi:
            text = fi.read()
            status_field = get_corresponding_regex("PPid")
            ppid_str = re.search(status_field, text, re.MULTILINE).group(1)
            ppid = int(ppid_str)
            parents[p] = ppid

            ppid_val = {}
            for isf_key in interesting_status_fields.keys():
                status_field = get_corresponding_regex(isf_key)
                isf_val = re.search(status_field, text, re.MULTILINE).group(1)
                transform = interesting_status_fields[isf_key]
                ppid_val[isf_key] = transform(isf_val)

            status[p] = ppid_val
    except EnvironmentError:
        # The process does not exist anymore
        # Remove it from the global list of all processes
        pids.remove(p)

result["status" ] = status
result["parents"] = parents


# TODO: Now parse file descriptors and add to result


if __name__ == '__channelexec__':
    channel.send(result)
elif __name__ == "__main__":
    print(result)
