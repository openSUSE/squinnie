"""
This script is intended to be run on the client remotely via execnet.
It can however also be called as a standalone script for testing purposes.

Unfortunately, to send a module via execnet, it has to be self-contained. This
results in this file being very long, as it is not possible to use external
imports, unless execnet_importhook gets ported to python2 or SUSE Enterprise
Linux gets shipped with Python 3 by default.
"""

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
from collections import OrderedDict
import os
import re
import copy
import codecs

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
for pid_str in os.listdir("/proc"):
    fp = os.path.join( "/proc", pid_str )
    if not os.path.isdir(fp):
        continue
    try:
        pid = int(pid_str)
    except ValueError:
        continue
    pids.append(pid)

parents = {}
status = {}
open_file_pointers = {}

for p in copy.copy(pids):
    try:
        status[p] = {}
        with codecs.open("/proc/%d/status" % p, "r", encoding="utf-8") as fi:
            text = fi.read()
            status_field = get_corresponding_regex("PPid")
            ppid_str = re.search(status_field, text, re.MULTILINE).group(1)
            ppid = int(ppid_str)
            parents[p] = ppid

            for isf_key in interesting_status_fields.keys():
                status_field = get_corresponding_regex(isf_key)
                isf_val = re.search(status_field, text, re.MULTILINE).group(1)
                transform = interesting_status_fields[isf_key]
                status[p][isf_key] = transform(isf_val)

        with codecs.open("/proc/%d/cmdline" % p, "r", encoding="utf-8") as fi:
            status[p]["cmdline"] = fi.read().replace("\n", "")

        open_file_pointers[p] = []
        fd_dir = "/proc/%d/fd/" % p
        for fd_str in os.listdir(fd_dir):

            resolved_symlink_name = os.path.realpath(fd_dir + fd_str)
            open_file_pointers[p].append(resolved_symlink_name)

    except EnvironmentError:
        # The process does not exist anymore
        # Remove it from the global list of all processes
        pids.remove(p)

with codecs.open("/etc/passwd", "r", encoding="utf-8") as fi:
    etcpasswd = fi.readlines()

name_uidgid = {}
for line in etcpasswd:
    line = line.replace("\n", "")
    regex = "^([a-zA-Z0-9\-]+):x:(\d+):(\d+):.*$"
    username = str(re.search(regex, line, re.MULTILINE).group(1))
    Uid      = int(re.search(regex, line, re.MULTILINE).group(2))
    Gid      = int(re.search(regex, line, re.MULTILINE).group(3))

    name_uidgid[username] = [Uid, Gid]

result["status" ] = status
result["parents"] = parents
result["open_file_pointers"] = open_file_pointers
result["name_uidgid"] = name_uidgid


if __name__ == '__channelexec__':
    channel.send(result)
elif __name__ == "__main__":
    print(result)
