"""
This script is intended to be run on the client remotely via execnet.
It can however also be called as a standalone script for testing purposes.
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
gid_uid_lambda = lambda a: tuple(a.split("\t"))

interesting_status_fields = { # TODO: Finish lambdas here... Code broken right now
    # "PPid",
    "CapInh" : cap_lambda,
    "CapPrm" : cap_lambda,
    "CapEff" : cap_lambda,
    "CapBnd" : cap_lambda,
    "CapAmb" : cap_lambda,
    "Gid"    : gid_uid_lambda,
    "Groups" : lambda a: a.split(),
    "Seccomp": lambda a: a == 1,
    "Uid"    : gid_uid_lambda,
}

def get_corresponding_regex(field_to_search_for):
    return "^%s:\s(.*)$" % (field_to_search_for)

def dict_to_sorteddict(d):
    return OrderedDict(sorted(d.items(), key=lambda t: t[0]))


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
                # print(isf_val)
                transform = interesting_status_fields[isf_key]
                ppid_val[isf_key] = transform(isf_val)

            ppid_val = dict_to_sorteddict(ppid_val)
            status[p] = ppid_val

    except EnvironmentError:
        # The process does not exist anymore
        # Ignore because this is not a problem
        pids.remove(p)
        continue

# print(len(status.keys()))
# print("len(parents.keys): %d" % len(parents.keys()))

# for key, value in parents.items():
#     if value not in status.keys():
#         # The process does not exist anymore
#         # Make the parent be PID 1
#         # We may want to change this behaviour in the future
#         parents[key] = 1

parents = dict_to_sorteddict(parents)
status  = dict_to_sorteddict(status)

children = {}
for p in pids:
    the_parent = parents[p]
    if not the_parent in children.keys():
        children[the_parent] = []
    children[the_parent].append(p)
children = dict_to_sorteddict(children)


data = OrderedDict()
data["status"  ] = status
data["parents" ] = parents
data["children"] = children

result = json.dumps(data, fi, indent=4)

if __name__ == '__channelexec__':
    channel.send(result)
# else:
#     print(result)

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
