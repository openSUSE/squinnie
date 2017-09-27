#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# security scanner - scan a system's security related information
# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author: Benjamin Deuter, Sebastian Kaim
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301 USA.

"""
This script is intended to run standalone for scanning an arbitrary node:

- either remotely via ssh/execnet.
- locally called as 'root'

Unfortunately, to send a module via execnet, it has to be self-contained. This
results in this file being somewhat longer that intended. Tt is not possible
to use external imports, unless execnet_importhook is available, which is only
available in python3 at the moment.

Target nodes may ship only python2, however.

You can find information about the structure of most /proc files in `man 5
proc`.
"""

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
import os
import sys
import errno


def isPython2():
    return sys.version_info.major == 2


class SlaveScanner(object):

    def __init__(self, collect_files = True):

        self.m_collect_files = collect_files
        self.m_protocols = {}

        import ctypes
        # for reading capabilities from the file system without relying on
        # existing external programs we need to directly hook into the libcap
        self.m_libcap = ctypes.cdll.LoadLibrary("libcap.so.2")
        self.m_libcap.cap_to_text.restype = ctypes.c_char_p
        self.m_have_root_priv = os.geteuid() == 0
        self.m_our_pid = os.getpid()

    def getCmdline(self, p):
        """Returns a tuple (cmdline, [parameters]) representing the command
        line belonging to the given process with PID `p`."""
        with open("/proc/{}/cmdline".format(p), "r") as fi:
            cmdline_str = fi.read().strip()
            cmdline_items = [str(item) for item in cmdline_str.split("\x00")]
            executable = cmdline_items[0]
            parameters = " ".join(cmdline_items[1:])
        return (executable, parameters)

    def getAllPids(self):
        """Returns a list of all process PIDs currently seen in /proc."""
        result = []

        for entry in os.listdir("/proc"):
            path = os.path.join( "/proc", entry )

            if not entry.isdigit():
                # not a PID dir
                continue
            elif not os.path.isdir(path):
                continue

            pid = int(entry)
            result.append(pid)

        return result

    def collectUserGroupMappings(self):
        """Collects dictionaries in self.m_uid_map and self.m_gid_map
        containing the name->id mappings of users and groups found in the
        system."""

        import pwd
        import grp

        self.m_uid_map = {}

        for user in pwd.getpwall():
            self.m_uid_map[user.pw_uid] = user.pw_name

        self.m_gid_map = {}
        for group in grp.getgrall():
            self.m_gid_map[group.gr_gid] = group.gr_name

    def collectProtocolInfo(self, protocol):
        """Collects protocol state information for ``protocol`` in
        self.m_protocols[``protocol``]."""

        with open("/proc/net/{}".format(protocol), "r") as f:
            table = [line.strip() for line in f.readlines()]
        # discard the column header
        table.pop(0)

        info = dict()
        self.m_protocols[protocol] = info

        for line in table:
            # IP based protocols
            if protocol != "unix":
                parts = line.split()
                l_host,l_port = parts[1].split(':')
                r_host,r_port = parts[2].split(':')
                inode = parts[9]
                info[inode] = [[l_host,l_port], [r_host,r_port]]
            else:
                parts = line.split()
                if len(parts) == 7:
                    # this is for unnamed unix domain sockets that have no
                    # path
                    parts.append("")
                inode = parts[6]
                info[inode] = parts[7]

    def collectProcessInfo(self):
        """
        Collect information about all running processes in the
        self.m_proc_info dictionary.
        """
        cap_lambda = lambda a: int(a, base=16)
        gid_uid_lambda = lambda a: tuple(int(i) for i in a.split("\t"))
        groups_lambda = lambda a: [int(i) for i in a.split()]
        seccomp_lambda = lambda a: int(a) == 1

        field_transforms = {
            "CapInh": cap_lambda,
            "CapPrm": cap_lambda,
            "CapEff": cap_lambda,
            "CapBnd": cap_lambda,
            "CapAmb": cap_lambda,
            "Gid": gid_uid_lambda,
            "Groups": groups_lambda,
            "Seccomp": seccomp_lambda,
            "Uid": gid_uid_lambda,
        }

        # PID -> dict() mapping, containing per process data
        status = {}
        # PID -> parent mapping which defines the process hierarchy
        parents = {}

        pids_to_remove = set()
        for p in self.getAllPids():
            if p == self.m_our_pid:
                # exclude ourselves, we're not so interesting ;)
                continue

            try:
                fields = {}
                with open("/proc/{}/status".format(p), "r") as fi:
                    for line in fi:
                        key, value = line.split(':', 1)
                        fields[key] = value.strip()

                status_pid = {}

                for key in field_transforms.keys():
                    transform_fnct = field_transforms[key]
                    status_pid[key] = transform_fnct(fields[key])

                exe, pars = self.getCmdline(p)
                status_pid["executable"] = exe
                status_pid["parameters"] = pars
                status_pid["root"] = os.path.realpath("/proc/{}/root".format(p))
                status_pid["open_files"] = self.getFdData(p)

                status[p] = status_pid
                parents[p] = int(fields["PPid"])

            except EnvironmentError as e:
                # The process does not exist anymore
                # Remove it from the global list of all processes
                pids_to_remove.add(p)

        # clean disappeared processes from the data structure
        for broken_pid in pids_to_remove:
            if broken_pid in status:
                del status[broken_pid]
            if broken_pid in parents:
                del parents[broken_pid]

        self.m_proc_info = {}
        self.m_proc_info["status"] = status
        self.m_proc_info["parents"] = parents

    def getFdData(self, pid):
        """Returns a dictionary describing the currently opened files of
        the process with PID ``pid``.

        The dictionary will consists of <FD> -> dict() pairs, where the dict()
        value contains the details of the file descriptor.
        """

        result = {}
        fd_dir = "/proc/{}/fd/".format(pid)
        fdinfo_dir = "/proc/{}/fdinfo".format(pid)

        for fd_str in os.listdir(fd_dir):
            file_path_name = os.path.join(fd_dir, fd_str)
            target = os.readlink(file_path_name)

            # we want the the target's properties here, not the symlink's, so
            # don't use lstat. NOTE: even if this is a seemingly broken
            # symlink for unnamed files like sockets, the stat will return
            # valid information.
            #
            # the lstat() seemingly returns file descriptor information like
            # read/write mode and such, which we parse in greater detail from
            # the fdinfo there later
            try:
                os_stat = os.stat(file_path_name)
                fd_identity_uid = os_stat.st_uid
                fd_identity_gid = os_stat.st_gid
                fd_perm_all = os_stat.st_mode
            except EnvironmentError as e:
                # probably the file was closed in the meantime
                continue

            # for open file description information we have to look here
            try:
                fields = dict()
                fdinfo = "{}/{}".format(fdinfo_dir, fd_str)
                with open(fdinfo, "r") as fi:
                    for line in fi:
                        key, value = [ p.strip() for p in line.split(':', 1) ]
                        fields[key] = value

                fd_data = {
                    "file_identity": {
                        "Uid": fd_identity_uid,
                        "Gid": fd_identity_gid,
                    },
                    "file_perm": fd_perm_all,
                    # "file_perm": {
                    #     "Uid"  : (fd_perm_all & stat.S_IRWXU) >> 6,
                    #     "Gid"  : (fd_perm_all & stat.S_IRWXG) >> 3,
                    #     "other": (fd_perm_all & stat.S_IRWXO) >> 0,
                    # },
                    # the flags are represented in octal
                    "file_flags": int(fields["flags"], 8),
                    "symlink": target,
                }
            except EnvironmentError as e:
                # probably the file was closed in the meantime
                continue

            result[fd_str] = fd_data

        return result

    def getProperties(self, filename, os_stat = None):
        """Gets the properties from the file object found in ``filename``"""
        properties = {}

        try:
            # returns an integer, like 36683988, which should be parsed as a
            # binary bitmask
            properties["caps"] = self.m_libcap.cap_get_file(filename)

            if not os_stat:
                os_stat = os.lstat(filename)
            properties["st_mode"] = os_stat.st_mode
            properties["st_uid" ] = os_stat.st_uid
            properties["st_gid" ] = os_stat.st_gid
        except EnvironmentError as e:
            print("Failed to lstat {}: {}".format(
                    filename, e
                ),
                file = sys.stderr
            )
            return None

        return properties

    def collectFilesystem(self):
        """Collects information about all file system objects and stores them
        in the self.m_filesystem dictionary."""

        # TODO: determine file system types and mount table

        # paths to exclude from the collection
        exclude = ["/.snapshots", "/proc", "/mounts", "/suse"]

        self.m_filesystem = {
            "subitems": {},
            "properties": {}
        }

        def walkErr(ex):
            """Is called from os.walk() when errors occur."""
            if not self.m_have_root_priv and ex.errno == errno.EACCES:
                # don't print a bunch of EACCES errors if we're not root.
                # Helpful for testing
                return
            print(ex.filename, ": ", ex, sep = '', file = sys.stderr)

        def getParentDict(path):
            """Find the correct dictionary in self.m_filesystem for inserting
            the directory info for ``path``."""

            ret = self.m_filesystem

            for node in os.path.dirname(path[1:]).split(os.path.sep):

                if not node:
                    continue

                ret = ret["subitems"][node]

            return ret

        for path, dirs, files in os.walk("/", topdown=True, onerror=walkErr):

            if path == "/":
                # remove excluded directories, only top-level dirs are
                # considered ATM
                dirs[:] = [d for d in dirs if os.path.join(path, d) not in exclude]
                self.m_filesystem["properties"] = self.getProperties(path)
                continue

            this_dir = os.path.basename(path)
            parent = getParentDict(path)

            path_dict = {
                "subitems": dict.fromkeys(files),
                "properties": self.getProperties(path)
            }
            parent["subitems"][this_dir] = path_dict

            for name in files:
                file_path = os.path.join(path, name)

                path_dict["subitems"][name] = {
                    "properties": self.getProperties(file_path)
                }

    def collect(self):

        result = {}

        self.collectProcessInfo()
        result["proc_data"] = self.m_proc_info["status"]
        result["parents"] = self.m_proc_info["parents"]
        self.collectUserGroupMappings()

        result['userdata'] = {
            "uids": self.m_uid_map,
            "gids": self.m_gid_map
        }

        result["networking"] = {}
        for prot in ("tcp", "tcp6", "udp", "udp6", "unix"):
            self.collectProtocolInfo(prot)
            result["networking"][prot] = self.m_protocols[prot]

        if self.m_collect_files:
            self.collectFilesystem()
            result["filesystem"] = self.m_filesystem

        # we're currently returning a single large dictionary containing all
        # collected information
        return result


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description = """
            Standalone script for collecting system status information like
            process tree and file system data.

            This script should be run as root, otherwise the collected
            information will be incomplete.
        """
    )

    parser.add_argument(
        "-o", "--output",
        help = "Where to write the pickled, collected data to. Pass '-' to write to stdout (default).",
        default = '-'
    )

    parser.add_argument(
        "--no-files", action = 'store_true',
        default = False,
        help = "Don't collect file system information. This will save a lot of time and space."
    )

    args = parser.parse_args()

    # on python3 we need to use the buffer sub-object to write binary data to
    # stdout
    pipe_out = sys.stdout if isPython2() else sys.stdout.buffer

    try:
        out_file = pipe_out if args.output == "-" else open(args.output, 'wb')
    except EnvironmentError as e:
        exit("Failed to open output file {}: {}".format(args.output, str(e)))

    if os.isatty(out_file.fileno()):
        exit("Refusing to output binary data to stdout connected to a terminal")

    scanner = SlaveScanner(collect_files = not args.no_files)
    result = scanner.collect()
    if isPython2():
        # for running locally via sudo: simply output the raw data structure
        # on stdout
        import cPickle as pickle
        protocol = pickle.HIGHEST_PROTOCOL
    else:
        import _pickle as pickle
        # constant missing in py3 on _pickle
        protocol = 4
    import gzip
    zip_out_file = gzip.GzipFile(fileobj=out_file, compresslevel=5)

    import cStringIO

    stream = cStringIO.StringIO()
    pickle.dump(result, stream, protocol=protocol)

    zip_out_file.write(stream.getvalue())


if __name__ == '__channelexec__':
    scanner = SlaveScanner()
    result = scanner.collect()
    channel.send( result )
elif __name__ == "__main__":
    main()

