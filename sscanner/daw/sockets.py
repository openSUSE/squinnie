#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author: Sebastian Kaim
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
import sscanner.file_mode as file_mode
import stat
import logging
import socket
import struct


class FdWrapper(object):
    """This class handles all file descriptors for a project."""

    def __init__(self, pid, fdinfo, uid, gid, daw_factory):
        self.m_pid = pid
        self.m_fdinfo = fdinfo
        self.m_uid = uid
        self.m_gid = gid
        self.m_file_descriptors = [FileDescriptor(fd, pid, info, uid, gid, daw_factory) for fd, info in fdinfo.items()]

    def __str__(self):
        return self.toString()

    def toString(self, verbose=False):
        lines = [fd.toString(verbose) for fd in self.m_file_descriptors]
        return "\n".join(sorted(lines)) or ""


class FileDescriptor(object):
    """Represents a file descriptor as open by a process."""

    def __init__(self, socket, pid, fdinfo, uid, gid, daw_factory):
        self.m_socket = socket
        self.m_info = fdinfo
        self.m_pid = pid
        self.m_uid = uid
        self.m_gid = gid
        self.m_daw_factory = daw_factory
        self.m_account_wrapper = daw_factory.getAccountWrapper()
        self.m_proc_wrapper = daw_factory.getProcWrapper()

    def getPseudoFileDesc(self, pseudo_label):
        """
        Returns a descriptive, formatted string for the given ``pseudo_label``
        which is the symlink content for pseudo files in /proc/<pid>/fd.
        """

        # Convert fds to more easy-to-read strings

        # this is a string like "<type>:<value>", where <value> is either an
        # inode of the form "[num]" or a subtype field like "inotify".
        _type, value = pseudo_label.split(':', 1)
        value = value.strip("[]")

        if _type == "pipe":
            logging.debug(pseudo_label)
            endpoints = self.m_proc_wrapper.getEndpointsForPipe(value)
            result = "{}: {:>6} {}".format(_type, value, '[unconnected]' if len(endpoints) < 2 else '')

            for endpoint in endpoints:
                if endpoint['pid'] != self.m_pid:
                    # this adds a line for each other connected process, but cuts of long process names
                    result += "\n{}--> {} [{}]".format(' ' * (len(_type) + 2), endpoint['pid'],
                         (endpoint['name'][:52] + '...') if endpoint['name'][55:] else endpoint['name'].strip())

        elif _type == "socket":
            result = "{}: {:>10}".format(
                _type, self.inodeToIdentifier(_type, int(value))
            )
        elif _type == "anon_inode":
            result = "{}: {}".format(_type, value)
        else:
            raise Exception("Unexpected pseudo file type " + _type)
        return result

    def inodeToIdentifier(self, _type, inode):
        """
        Returns a human readable string describing the given node number.

        This is helpful for pseudo files found in /proc/<pid>/fd, that for
        some types of files contain the inode number which can be looked up in
        other data structures.

        :param str _type: The type of the inode like "socket"
        :param int inode: The inode number to lookup.
        """

        if _type != "socket":
            raise Exception("Can only translate socket inodes for now")

        networking_wrapper = self.m_daw_factory.getNetworkingWrapper()

        result = []
        for transport_protocol in networking_wrapper.getProtocols():
            transport_dict = networking_wrapper.getProtocolData(transport_protocol)
            if not transport_dict:
                continue
            inode_entry = transport_dict.get(str(inode), -1)

            if inode_entry == -1:
                continue

            # a named unix domain socket
            if transport_protocol == "unix":
                if inode_entry == "":  # unnamed unix domain socket
                    inode_entry = "<anonymous>"
                else:  # named or abstract unix domain socket
                    props = self.getFileProperties(inode_entry)
                    if props:
                        st_mode = props['st_mode']
                        # permissions = file_mode.getModeString(st_mode)
                        permissions = format(st_mode & 0x01FF, 'o')
                    else:
                        permissions = "unkown"
                    inode_entry = "{} (file permissions: {})".format(
                        inode_entry, permissions
                    )

                result.append("{}:{}".format(transport_protocol, inode_entry))
            else:  # TCP or UDP socket with IP address and port
                sc = NetworkSocket.fromTuple(inode_entry, transport_protocol)

                result.append(str(sc))
                logging.debug(str(sc))

        result = "|".join(result)

        if result:
            return result
        else:
            return "<port not found, inode: {:>8}>".format(inode)

    def getFileProperties(self, filename):
        """Returns the properties of a given file path in the file system. Or
        an empty dictionary on failure."""
        fs_wrapper = self.m_daw_factory.getFsWrapper()

        return fs_wrapper.getFileProperties(filename)

    def __str__(self):
        return self.toString()

    def toString(self, verbose=False):
        symlink = self.m_info["symlink"]

        flags = file_mode.getFdFlagLabels(self.m_info["file_flags"])
        file_perm = {
            "Uid": (self.m_info["file_perm"] & stat.S_IRWXU) >> 6,
            "Gid": (self.m_info["file_perm"] & stat.S_IRWXG) >> 3,
            "other": (self.m_info["file_perm"] & stat.S_IRWXO) >> 0,
        }
        perms_octal = ''.join(
            [str(file_perm[key]) for key in ('Uid', 'Gid', 'other')]
        )

        # since all paths a absolute, real paths start with /
        is_pseudo_file = not symlink.startswith('/')

        # pseudo files: sockets, pipes, ...
        if is_pseudo_file:

            type, inode = symlink.split(':', 1)
            line = self.getPseudoFileDesc(symlink)

            if verbose:
                line = "{:>5}: ".format(self.m_socket) + line
            if type == "socket":
                line = "{} (permissions: {})".format(line, perms_octal)
            if flags:
                line = "{} (flags: {})".format(line, "|".join(flags))

            return line
        else:
            # real files on disk

            file_identity = self.m_info["file_identity"]

            color_it = False
            for uid_type in self.m_uid:

                user_identity = {
                    "Uid": uid_type,
                    "Gid_set": self.m_gid,
                }

                if not file_mode.canAccessFile(
                        user_identity,
                        file_identity,
                        file_perm
                ):
                    color_it = True

            line = symlink
            # if color_it:
            #     line = self.getColored(line)

            if verbose:
                line = "{:>5}: ".format(self.m_socket.fd) + line
            line = "{} (permissions: {}, owned by {}:{})".format(line, perms_octal,
                                                                 self.m_account_wrapper.getNameForUid(self.m_uid[0]),
                                                                 self.m_account_wrapper.getNameForGid(self.m_gid[0]))

            if flags:
                line = "{} (flags: {})".format(line, "|".join(flags))

            return line


class NetworkSocket(object):
    """This class represents a network socket."""

    def __init__(self, protocol, ip_version, local_endpoint, local_port, remote_endpoint, remote_port):
        self.m_protocol = protocol
        self.m_ip_version = ip_version
        self.m_local_endpoint = NetworkEndpoint(ip_version, local_endpoint, local_port)
        self.m_remote_endpoint = NetworkEndpoint(ip_version, remote_endpoint, remote_port)

    @staticmethod
    def fromTuple(socketdata, protocol):
        ipv = 4
        if len(protocol) > 3:  # tcp6 or udp6
            ipv = 6
            protocol = protocol[:3]

        data = NetworkSocket(protocol, ipv, socketdata[0][0], int(socketdata[0][1], 16),
                             socketdata[1][0], int(socketdata[1][1], 16))
        return data

    def __str__(self):
        outp = '{}{}: {}'.format(self.m_protocol, self.m_ip_version, str(self.m_local_endpoint))

        if self.m_remote_endpoint.isConnected():
            outp += ' <--> {}'.format(str(self.m_remote_endpoint))
        else:
            outp += ' listening/waiting'
        return outp


class NetworkEndpoint(object):
    """Represents a network endpoint with IP and port."""

    def __init__(self, ip_version, ip, port):
        self.m_ip_version = ip_version
        self.m_ip = ip
        self.m_port = port

    def isConnected(self):
        # the ip can be zero when listening on all IPs
        return self.m_port != 0

    @staticmethod
    def IPv6ToString(ipv6):
        packed = struct.unpack('>IIII', ipv6.decode('hex'))
        addr = struct.pack('@IIII', *packed)
        return socket.inet_ntop(socket.AF_INET6, addr)

    def __str__(self):
        if self.m_ip_version == 4:
            return '{}:{}'.format(socket.inet_ntoa(struct.pack('<L', int(self.m_ip, 16))), str(self.m_port))
        else:
            return '[{}]:{}'.format(self.IPv6ToString(self.m_ip), str(self.m_port))
