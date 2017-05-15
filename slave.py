#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

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
import pwd
import grp



def get_uid_name():

    uid_name = {}
    for user in pwd.getpwall():
        uid_name[user.pw_uid] = user.pw_name

    return uid_name


def get_gid_name():

    gid_name = {}
    for group in grp.getgrall():
        gid_name[group.gr_gid] = group.gr_name

    return gid_name



def collect_data():

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
        return "^{}:\s(.*)$".format(field_to_search_for)


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
    open_file_descriptors = {}

    all_uids = set()
    all_gids = set()

    for p in copy.copy(pids):
        try:
            status[p] = {}
            with open("/proc/{}/status".format(p), "r") as fi:
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

                all_uids.add(status[p]["Uid"])
                all_gids.add(status[p]["Gid"])

            with open("/proc/{}/cmdline".format(p), "r") as fi:
                cmdline_str = fi.read().replace("\n", "")
                cmdline_items = [str(item) for item in cmdline_str.split("\x00")]
                executable = cmdline_items[0]
                parameters = " ".join(cmdline_items[1:])

                status[p]["executable"] = executable
                status[p]["parameters"] = parameters


            status[p]["real_files"] = {}
            status[p]["pseudo_files"] = {}
            fd_dir = "/proc/{}/fd/".format(p)
            for fd_str in os.listdir(fd_dir):

                file_path_name = fd_dir + fd_str
                resolved_symlink_name = os.path.realpath(file_path_name)

                fd_identity_uid = os.stat(file_path_name).st_uid
                fd_identity_gid = os.stat(file_path_name).st_gid
                fd_perm_all     = os.stat(file_path_name).st_mode & 0b111111111

                fd_data = {
                    "file_identity": {
                        "Uid": fd_identity_uid,
                        "Gid": fd_identity_gid,
                    },

                    "file_perm"    : {
                        "Uid"  : (fd_perm_all & 0b111000000) >> 6,
                        "Gid"  : (fd_perm_all & 0b000111000) >> 3,
                        "other":  fd_perm_all & 0b000000111,
                    }
                }

                if ":" in resolved_symlink_name:
                    file_type = "pseudo_files"
                else:
                    file_type = "real_files"

                status[p][file_type][resolved_symlink_name] = fd_data

        except EnvironmentError:
            # The process does not exist anymore
            # Remove it from the global list of all processes
            pids.remove(p)


    result["proc_data"] = status
    result["parents"  ] = parents
    result["uid_name" ] = get_uid_name()
    result["gid_name" ] = get_gid_name()

    return result


if __name__ == '__channelexec__' or __name__ == "__main__":
    result = collect_data()

if __name__ == '__channelexec__':
    channel.send( collect_data() )
