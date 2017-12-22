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


class Scanner(object):

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
        self.m_mqueue_fs = []  # list of mqueue mounts. This is required to determine mqueue file descriptors

    @staticmethod
    def getCmdline(pid, tid=None):
        """Returns a tuple (cmdline, [parameters], full_cmdline) representing the command line belonging to the given
        process with PID pid. If tid is given, the command line of the thread with tid will be returned"""
        path = "/proc/{pid}{task}/cmdline".format(pid=pid, task="/task/{id}".format(id=tid) if tid is not None else '')
        with open(path, "r") as fi:
            cmdline_str = fi.read().strip()
            cmdline_items = [str(item) for item in cmdline_str.split("\x00")]
            executable = cmdline_items[0]
            parameters = " ".join(cmdline_items[1:])
        return executable, parameters, cmdline_str

    def getAllPids(self):
        """Returns a list of all process PIDs currently seen in /proc."""
        result = []

        for entry in os.listdir("/proc"):
            path = os.path.join("/proc", entry)

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

        with open("/proc/net/{prot}".format(prot = protocol), "r") as f:
            table = [line.strip() for line in f.readlines()]
        # discard the column header
        table.pop(0)

        info = dict()
        self.m_protocols[protocol] = info

        for line in table:
            parts = line.split()

            if protocol == "netlink":
                inode = parts[-1]
                info[inode] = parts[1]  # the Eth
            elif protocol == "packet":
                inode = parts[-1]
                info[inode] = parts
            # IP based protocols
            elif protocol != "unix":
                l_host, l_port = parts[1].split(':')
                r_host, r_port = parts[2].split(':')
                inode = parts[9]
                info[inode] = [[l_host, l_port], [r_host, r_port]]
            else:
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
                fields, status_pid = self.getProcessedProcessInfo(field_transforms, p)

                exe, pars, cmdline = self.getCmdline(p)
                status_pid["executable"] = exe if exe else '[{n}]'.format(n=fields['Name'])
                status_pid["parameters"] = pars
                status_pid["cmdline"] = cmdline  # this value is needed to compare it with the threads
                status_pid["root"] = os.path.realpath("/proc/{pid}/root".format(pid = p))
                status_pid["open_files"] = self.getFdData(p)

                status_pid['threads'] = self.getProcessedThreadInfosForProcess(p, field_transforms)

                stat_data = self.getStatData(p)
                status_pid.update(stat_data)  # merge all data we need from stat to status_pid

                status_pid["parent"] = int(fields["PPid"])
                if 'Umask' in fields:
                    status_pid['Umask'] = int(fields['Umask'], 8)
                parents[p] = status_pid["parent"]
                status[p] = status_pid

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

    @staticmethod
    def getProcessInfo(pid, tid=None):
        """
        Reads the process/thread info from proc. It uses /proc/pid/status for processes and /proc/pid/task/kid for
        threads.
        :param pid: The pid of the process.
        :param tid: The thread id if thread data should be read.
        :return: The list of fields in stat
        """
        is_thread = tid is not None
        path = "/proc/{pid}".format(pid=pid)
        if is_thread:
            path = "{path}/task/{tid}".format(path=path, tid=tid)
        path += "/status"

        fields = {}
        with open(path, "r") as fi:
            for line in fi:
                key, value = line.split(':', 1)
                fields[key] = value.strip()

        return fields

    @staticmethod
    def getProcessedProcessInfo(transforms, pid, tid=None):
        """
        Reads the process/thread info from proc. It uses /proc/pid/status for processes and /proc/pid/task/kid for
        threads. After retrieving the data, it will be processed with the functions given in the transform parameter.
        :param transforms: The transformation functions for the field data.
        :param pid: The pid of the process.
        :param tid: The thread id if thread data should be read.
        :return: A tuple of (data, processed_data)
        """
        fields = Scanner.getProcessInfo(pid, tid)
        processed_data = {}

        for key in transforms.keys():
            val = fields.get(key, None)
            if val is None:
                # e.g. on SLES-11 there is no CapAmb
                continue
            transform_fnct = transforms[key]
            processed_data[key] = transform_fnct(fields[key])

        return fields, processed_data

    @staticmethod
    def getProcessedThreadInfosForProcess(pid, transforms):
        """
        Collects thread information of a process.
        :param transforms: The transform functions to refine the data for each thread.
        :param pid: The pid of the target.
        :return: A dict of tid -> processed_data
        """
        threadlist = os.listdir("/proc/{pid}/task".format(pid=pid))

        data = {}
        for tid in threadlist:
            fields, threadinfo = Scanner.getProcessedProcessInfo(transforms, pid, tid)

            exe, pars, cmdline = Scanner.getCmdline(pid, tid)
            threadinfo["executable"] = exe if exe else '[{n}]'.format(n=fields['Name'])
            threadinfo["parameters"] = pars
            threadinfo["cmdline"] = cmdline  # this value is needed to compare it with the threads
            data[tid] = threadinfo
        return data

    @staticmethod
    def getCmdlineForThread(pid, tid):
        """
        Returns the cmdline for a thread.
        :param pid: The pid of the parent process.
        :param tid: The tid of the thread.
        :return:
        """
        path = "/proc/{pid}/task/{tid}/cmdline".format(pid=pid, tid=tid)
        with open(path, "r") as fi:
            return fi.readline()

    def getFdData(self, pid):
        """Returns a dictionary describing the currently opened files of
        the process with PID ``pid``.

        The dictionary will consists of <FD> -> dict() pairs, where the dict()
        value contains the details of the file descriptor.
        """

        result = {}
        fd_dir = "/proc/{pid}/fd/".format(pid = pid)
        fdinfo_dir = "/proc/{pid}/fdinfo".format(pid = pid)

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
                fdinfo = "{dir}/{base}".format(dir=fdinfo_dir, base=fd_str)
                fdpath = "{dir}/{base}".format(dir=fd_dir, base=fd_str)
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
                    "file_flags": int(fields["flags"], 8),
                    "symlink": target,
                }

                # all mqueue symlinks look like '/test'
                if os.path.dirname(target) == '/':

                    # let's check if the linked file is on an mqueue file system
                    st_dev = os.stat(fdpath).st_dev

                    # we need to cast major/miner to string as it's parsed that way from mountinfo
                    if (str(os.major(st_dev)), str(os.minor(st_dev))) in self.m_mqueue_fs:
                        fd_data['queue'] = os.path.basename(target)

            except EnvironmentError as e:
                # probably the file was closed in the meantime
                continue

            result[fd_str] = fd_data

        return result

    def getProperties(self, filename, type, os_stat=None):
        """Gets the properties from the file object found in ``filename``"""
        properties = {}

        try:
            # returns an integer, like 36683988, which should be parsed as a binary bitmask
            properties["caps"] = self.m_libcap.cap_get_file(filename)

            if not os_stat:
                os_stat = os.lstat(filename)
            properties["st_mode"] = os_stat.st_mode
            properties["st_uid"] = os_stat.st_uid
            properties["st_gid"] = os_stat.st_gid
            properties["type"] = type
        except EnvironmentError as e:
            print("Failed to lstat {path}: {reason}".format(
                    path=filename, reason=e
                ),
                file=sys.stderr
            )

            # return a basic construct as the file will be recorded anyway
            return {
                "caps": 0,
                "st_mode": 0,
                "st_uid": -1,
                "st_gid": -1,
                "type": type
            }

        return properties

    def collectFilesystems(self):
        """
        Collect information about mounted filesystems from /proc/self/mountinfo
        :return: A list of dicts, each describing a mountpoint
        """
        # see man 5 proc for info about those fields
        # super options are missing
        keys = [
            'mountid', 'parent', 'st_dev', 'root', 'mountpoint', 'options', 'type', 'device', 'fsckindex', 'fs_options'
        ]
        ret = []

        with open("/proc/self/mountinfo", "r") as f:
            for line in f.readlines():
                data = line.strip().split()

                # So, just to delight the people who write parsers for this file, the kernel has decided that mountinfo
                # needs to contain several 'optional fields' which can be either be 0 or up to several. And, instead of
                # putting those in the end, those are from position 7 (6 if zero-based) on and are delimited by a field
                # containing only '-'. That's why parsing this file takes 20 lines instead of three.
                separator_index = data.index('-')
                optional_fields = dict([field.split(':', 1) for field in data[6:separator_index]])

                dc = dict(zip(keys, data[:5] + data[separator_index:]))
                dc['optional_fields'] = optional_fields
                ret.append(dc)

                if dc['type'] == 'mqueue':
                    self.m_mqueue_fs.append(tuple(dc['st_dev'].split(':', 1)))

        return ret

    def collectFilesystem(self):
        """Collects information about all file system objects and stores them
        in the self.m_filesystem dictionary."""

        # paths to exclude from the collection
        exclude = ["/.snapshots", "/proc", "/mounts", "/suse"]

        self.m_filesystem = {
            "subitems": {},
            "properties": self.getProperties("/", type='d')
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
            if path == '/':
                continue

            cont = True
            for excluded in exclude:
                if path.startswith(excluded):
                    # don't descend further into excluded directories
                    dirs[:] = []
                    cont = False
                    break
            if not cont:
                continue

            this_dir = os.path.basename(path)
            parent = getParentDict(path)

            path_dict = {
                "subitems": dict.fromkeys(files),
                "properties": self.getProperties(path, type='d')
            }
            parent["subitems"][this_dir] = path_dict

            for name in files:
                file_path = os.path.join(path, name)

                path_dict["subitems"][name] = {
                    "properties": self.getProperties(file_path, type='f')
                }

            for link in [link for link in
                         [os.path.join(os.path.realpath(path), _dir) for _dir in dirs]
                         if os.path.islink(link)]:
                # walk will only list symlinks to directorys in the 'dirs' variable. Since it's configured to not follow
                # symlinks it will never appear anywhere else and therefore be ignored. So it get's some special
                # treatment here ;)
                path_dict["subitems"][link] = {
                    "properties": self.getProperties(link, type='l'),
                    "target": os.path.realpath(link)
                }

    def collect(self):

        result = {}

        # we need to collect the systemdata first in order to have the data for detecting mqueue sockets
        result['systemdata'] = self.collectSystemData()

        self.collectProcessInfo()
        result["proc_data"] = self.m_proc_info["status"]
        result["parents"] = self.m_proc_info["parents"]
        self.collectUserGroupMappings()

        result['userdata'] = {
            "uids": self.m_uid_map,
            "gids": self.m_gid_map
        }

        result["networking"] = {}
        for prot in ("tcp", "tcp6", "udp", "udp6", "unix", "netlink", "packet"):
            self.collectProtocolInfo(prot)
            result["networking"][prot] = self.m_protocols[prot]

        if self.m_collect_files:
            self.collectFilesystem()
            result["filesystem"] = self.m_filesystem

        self.collectSysVIpcInfo()
        result["sysvipc"] = self.m_sysvipc

        # we're currently returning a single large dictionary containing all
        # collected information
        return result

    def collectSysVIpcInfo(self):
        self.m_sysvipc = {}

        for ipctype in ['msg', 'sem', 'shm']:
            with open("/proc/sysvipc/{f}".format(f=ipctype), "r") as f:
                table = [line.strip() for line in f.readlines()]

            header = table.pop(0).split()
            self.m_sysvipc[ipctype] = []

            for line in table:
                lineparts = line.split()
                linedata = {}

                for i in range(len(lineparts)):
                    linedata[header[i]] = lineparts[i]

                self.m_sysvipc[ipctype].append(linedata)

    @staticmethod
    def getStatData(pid):
        """
        Collect the data from /proc/<pid>/stat
        :param pid: The pid to get stats about.
        :return: The known indices as dict.
        """
        # this dict maps the indices from the data in stat to names
        # those are in `man 5 proc` (note that the numbers in there are 1-based while the dict is 0-based)
        name_mapping = {
            4: 'pgroup',
            5: 'session',
            21: 'starttime'
        }

        path = "/proc/{pid}/stat".format(pid=pid)
        with open(path, "r") as fi:
            raw_data = fi.read().strip().split()
            data = {}

            for index, name in name_mapping.items():
                data[name] = raw_data[index]

            return data

    def collectSystemData(self):
        result = {}

        with open("/proc/uptime", "r") as fi:
            raw_data = fi.read().strip().split()
            result['uptime'] = raw_data[0]

        sysconf = {}
        for key in os.sysconf_names.keys():
            try:
                sysconf[key] = os.sysconf(key)
            except OSError:
                # some keys can't be collected
                pass

        result['sysconf'] = sysconf
        result['mounts'] = self.collectFilesystems()
        return result


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="""
            Standalone script for collecting system status information like
            process tree and file system data.

            This script should be run as root, otherwise the collected
            information will be incomplete.
        """
    )

    parser.add_argument(
        "-o", "--output",
        help="Where to write the pickled, collected data to. Pass '-' to write to stdout (default).",
        default='-'
    )

    parser.add_argument(
        "--no-files", action='store_true',
        default=False,
        help="Don't collect file system information. This will save a lot of time and space."
    )

    args = parser.parse_args()

    # on python3 we need to use the buffer sub-object to write binary data to
    # stdout
    pipe_out = sys.stdout if isPython2() else sys.stdout.buffer

    try:
        out_file = pipe_out if args.output == "-" else open(args.output, 'wb')
    except EnvironmentError as e:
        exit("Failed to open output file {path}: {reason}".format(
            path = args.output,
            reason = str(e))
        )

    if os.isatty(out_file.fileno()):
        exit("Refusing to output binary data to stdout connected to a terminal")

    scanner = Scanner(collect_files=not args.no_files)
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
    scanner = Scanner()
    result = scanner.collect()
    channel.send(result)
elif __name__ == "__main__":
    main()

