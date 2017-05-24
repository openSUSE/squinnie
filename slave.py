#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

"""
This script is intended to be run on the client remotely via execnet.
It can however also be called as a standalone script for testing purposes.

Unfortunately, to send a module via execnet, it has to be self-contained. This
results in this file being very long, as it is not possible to use external
imports, unless execnet_importhook gets ported to Python 2 or SUSE Enterprise
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
import stat



if __name__ == '__channelexec__' or __name__ == "__main__":
    def get_uid_gid_name():
        uid_name = {}
        for user in pwd.getpwall():
            uid_name[user.pw_uid] = user.pw_name
        gid_name = {}
        for group in grp.getgrall():
            gid_name[group.gr_gid] = group.gr_name

        result = {}
        result["uid_name"] = uid_name
        result["gid_name"] = gid_name
        return result



    def load_network(transport_protocol):
        with open("/proc/net/{}".format(transport_protocol),"r") as f:
            content = f.readlines()
        content.pop(0)
        result = {}
        for line in content:
            if transport_protocol != "unix":
                line_array = [x for x in line.split(' ') if x !='']
                l_host,l_port = line_array[1].split(':')
                r_host,r_port = line_array[2].split(':')
                inode = line_array[9]
                result[inode] = [[l_host,l_port], [r_host,r_port]]
            else:
                line_array = [x for x in line.split()]
                if len(line_array) == 7:
                    line_array.append("")
                inode = line_array[6]
                result[inode] = line_array[7]
        return result



    def get_all_files():
        result = {}
        for dirpath, dirnames, filenames in os.walk("/"):
            for a_file in filenames:
                file_path_name = os.path.join(dirpath, a_file)
                file_properties = []
                result[file_path_name] = file_properties
        return result



    def get_directory_structure():
        """
        Creates a nested dictionary that represents the folder structure of rootdir
        http://code.activestate.com/recipes/577879-create-a-nested-dictionary-from-oswalk/
        """
        result = {}
        for path, dirs, files in os.walk("/"):
            folders = path[1:].split(os.sep)
            subdir = dict.fromkeys(files)
            parent = reduce(dict.get, folders[:-1], result)
            parent[folders[-1]] = subdir
        return result



    def get_cmdline(p):
        with open("/proc/{}/cmdline".format(p), "r") as fi:
            cmdline_str = fi.read().replace("\n", "")
            cmdline_items = [str(item) for item in cmdline_str.split("\x00")]
            executable = cmdline_items[0]
            parameters = " ".join(cmdline_items[1:])
        return (executable, parameters)



    def get_status_parents():
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

        def get_val(field_to_search_for, text):
            return re.search("^{}:\s(.*)$".format(field_to_search_for), text, re.MULTILINE).group(1)

        status = {}
        parents = {}

        pids_to_remove = set()
        for p in get_all_pids():
            try:
                with open("/proc/{}/status".format(p), "r") as fi:
                    text = fi.read()
                status_pid = {}
                for isf_key in interesting_status_fields.keys():
                    transform_fnct = interesting_status_fields[isf_key] # lambda function
                    status_pid[isf_key] = transform_fnct(get_val(isf_key, text))

                cmdline = get_cmdline(p)
                status_pid["executable"] = cmdline[0]
                status_pid["parameters"] = cmdline[1]
                status_pid["root"] = os.path.realpath("/proc/{}/root".format(p))
                status_pid["open_files"] = get_fd_data(p)

                status[p] = status_pid
                parents[p] = int(get_val("PPid", text))

            except (OSError, IOError, EnvironmentError) as e:
                # The process does not exist anymore
                # Remove it from the global list of all processes
                pids_to_remove.add(p)

        for broken_pid in pids_to_remove:
            if broken_pid in status:
                del status[broken_pid]

        result = {}
        result["status"] = status
        result["parents"] = parents
        return result



    def get_fd_data(p):
        result = {}
        fd_dir = "/proc/{}/fd/".format(p)
        for fd_str in os.listdir(fd_dir):
            file_path_name = os.path.join(fd_dir, fd_str)
            resolved_symlink_name = os.path.realpath(file_path_name)

            the_stats = os.stat(file_path_name)
            fd_identity_uid = the_stats.st_uid
            fd_identity_gid = the_stats.st_gid
            fd_perm_all     = the_stats.st_mode

            with open("/proc/{}/fdinfo/{}".format(p, fd_str), "r") as fi:
                tmp_str = fi.read()
            tmpdata = dict(item.split(":\t") for item in tmp_str.strip().split("\n")[:3])

            fd_data = {
                "file_identity": {
                    "Uid": fd_identity_uid,
                    "Gid": fd_identity_gid,
                },
                "file_perm": {
                    "Uid"  : (fd_perm_all & stat.S_IRWXU) >> 6,
                    "Gid"  : (fd_perm_all & stat.S_IRWXG) >> 3,
                    "other": (fd_perm_all & stat.S_IRWXO) >> 0,
                },
                "file_flags": int(tmpdata["flags"], 8),
                "symlink": resolved_symlink_name,
            }

            result[fd_str] = fd_data
        return result



    def get_all_pids():
        result = []
        # traverse root directory, and list directories as dirs and files as files
        for pid_str in os.listdir("/proc"):
            fp = os.path.join( "/proc", pid_str )
            if not os.path.isdir(fp):
                continue
            try:
                pid = int(pid_str)
            except ValueError:
                continue
            result.append(pid)
        return result


    def get_properties(path):
        """Gets the properties either from a file or a directory"""
        properties = {}
        try:
            os_stat = os.stat(path)
            properties["st_mode"] = os_stat.st_mode
            properties["st_uid" ] = os_stat.st_uid
            properties["st_gid" ] = os_stat.st_gid
        except OSError:
            properties["st_mode"] = None
            properties["st_uid" ] = None
            properties["st_gid" ] = None
        return properties

    def get_filesystem():
        filesystem = {}
        exclude = ["/.snapshots", "/proc"]
        for path, dirs, files in os.walk("/", topdown=True):
            dirs[:] = [d for d in dirs if os.path.join(path, d) not in exclude]
            if path == "/":
                continue
            print(path)
            folders = path[1:].split(os.sep)
            subdir = dict.fromkeys(files)
            lst = folders[:-1]
            the_directories = ["subitems"] * (len(lst) * 2)
            the_directories[0::2] = lst
            parent = reduce(dict.get, the_directories, filesystem)
            parent[folders[-1]] = {}
            parent[folders[-1]]["subitems"    ] = subdir
            parent[folders[-1]]["properties"] = get_properties(path)

            for a_file in files:
                parent[folders[-1]]["subitems"][a_file] = {}
                file_path_name = os.path.join(path, a_file)
                parent[folders[-1]]["subitems"][a_file]["properties"] = get_properties(file_path_name)

        return filesystem



    def collect_data():

        # Send one big dictionary at the end
        result = {}
        status_parents = get_status_parents()
        result["proc_data"] = status_parents["status"]
        result["parents"  ] = status_parents["parents"]
        uid_gid = get_uid_gid_name()
        result["uid_name" ] = uid_gid["uid_name"]
        result["gid_name" ] = uid_gid["gid_name"]
        result["tcp"      ] = load_network("tcp")
        result["tcp6"     ] = load_network("tcp6")
        result["udp"      ] = load_network("udp")
        result["udp6"     ] = load_network("udp6")
        result["unix"     ] = load_network("unix")
        result["filesystem"] = get_filesystem()

        return result


    result = collect_data()

if __name__ == '__channelexec__':
    channel.send( result )
