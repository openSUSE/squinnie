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
import squinnie.file_mode as file_mode
import stat
import logging
import socket
import struct
from functools import total_ordering


class FdWrapper(object):
    """This class handles all file descriptors for a project."""

    def __init__(self, pid, fdinfo, uid, gid, daw_factory):
        self.m_pid = pid
        self.m_fdinfo = fdinfo
        self.m_uid = uid
        self.m_gid = gid
        self.m_daw_factory = daw_factory
        self.m_file_descriptors = [FileDescriptor(fd, pid, info, uid, gid, daw_factory) for fd, info in fdinfo.items()]

    def __str__(self):
        return self.toString()

    def toString(self, verbose=False):
        lines = [fd.toString(verbose) for fd in sorted(self.m_file_descriptors)] + self.getShm()
        return "\n".join(sorted(lines)) or ""

    def getShm(self):
        proc_wrapper = self.m_daw_factory.getProcWrapper()
        endpoints = proc_wrapper.getShmsForPid(self.m_pid)
        lines = []

        for inode, shm in endpoints.items():
            type = 'shm'
            if shm['name'].startswith('sem.'):
                shm['name'] = shm['name'][4:]  # strip the sem. prefix
                type = 'semaphore'

            result = "{}: '{}'".format(type, shm['name'])

            for pid, endpoint in shm['pids'].items():
                if pid != self.m_pid:
                    # this adds a line for each other connected process, but cuts of long process names
                    logging.debug(endpoint)
                    result += "\n  --> {} [{}]".format(endpoint['pid'],
                                                  (endpoint['name'][:52] + '...') if endpoint['name'][55:]
                                                  else endpoint['name'].strip())
            lines.append(result)
        return lines


@total_ordering
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
        self.symlink = self.m_info["symlink"]

        # since all paths a absolute, real paths start with / , but queues do as well
        self.is_pseudo_file = not self.symlink.startswith('/') or 'queue' in self.m_info
        self.is_queue = 'queue' in self.m_info

        self._extractInfo()

    def __lt__(self, other):
        if self.type != other.type:
            return self.type.__lt__(other.type)
        else:
            return self.inode.__lt__(other.inode) if self.type != 'file' else self.fd_number.__lt__(other.fd_number)

    def _extractInfo(self):

        if self.is_queue:
            self.type = 'queue'
            self.inode = self.m_info['queue']
        elif self.is_pseudo_file:
            self.type, self.inode = self.symlink.split(':', 1)
        else:
            self.type = 'file'
            # it's actually the filedescriptor number
            self.fd_number = self.m_socket

    def getPseudoFileDesc(self, pseudo_label):
        """
        Returns a descriptive, formatted string for the given ``pseudo_label``
        which is the symlink content for pseudo files in /proc/<pid>/fd.
        :param pseudo_label: The label of the fd (the target of the symlink in /proc/<pid>/fd).
        """

        # Convert fds to more easy-to-read strings

        # this is a string like "<type>:<value>", where <value> is either an
        # inode of the form "[num]" or a subtype field like "inotify".
        namespaces = ['net', 'ipc', 'mnt', 'pid', 'uts']
        _type, value = (self.type, self.inode)
        value = value.strip("[]")

        if _type == "pipe":
            logging.debug(pseudo_label)
            endpoints = self.m_proc_wrapper.getEndpointsForPipe(value)

            # we need to extract our fd number from the endpoints as it is not handed through to this class currently
            fd = self.getFdFromEndpointDict(endpoints, self.m_pid)
            result = "{}: {:>6} {} @fd {}".format(_type, value, '[no endpoint]' if len(endpoints) < 2 else '', fd)

            for endpoint in endpoints:
                if endpoint['pid'] != self.m_pid:
                    # this adds a line for each other connected process, but cuts of long process names
                    result += "\n{}--> {} [{} @fd {}]".format(' ' * (len(_type) + 2), endpoint['pid'],
                                                       (endpoint['name'][:52] + '...') if endpoint['name'][55:] else
                                                       endpoint['name'].strip(), endpoint['fd'])

        elif _type == "socket":
            logging.debug(pseudo_label)
            endpoints = self.m_proc_wrapper.getEndpointsForSocket(value)
            identifier = self.inodeToIdentifier(_type, int(value))
            
            # we need to extract our fd number from the endpoints as it is not handed through to this class currently
            fd = self.getFdFromEndpointDict(endpoints, self.m_pid)
            result = "{}: {:>10} @fd {}".format(_type, identifier, fd)

            for endpoint in endpoints:
                if endpoint['pid'] != self.m_pid:
                    # this adds a line for each other connected process, but cuts of long process names
                    result += "\n{}--> {} [{} @fd {}]".format(' ' * (len(_type) + 2), endpoint['pid'],
                                                       (endpoint['name'][:52] + '...') if endpoint['name'][55:] else
                                                       endpoint['name'].strip(), endpoint['fd'])
            # result = "{}: {:>10}".format(
            #     _type, self.inodeToIdentifier(_type, int(value))
            # )
        elif _type == "anon_inode":
            result = "{}: {}".format(_type, value)
        elif _type == "queue":
            endpoints = self.m_proc_wrapper.getEndpointsForQueue(value)
            fd = self.getFdFromEndpointDict(endpoints, self.m_pid)

            result = "{} '{}' @fd {}".format(_type, value, fd)

            for endpoint in endpoints:
                if endpoint['pid'] != self.m_pid:
                    # this adds a line for each other connected process, but cuts of long process names
                    result += "\n{}--> {} [{} @fd {}]".format(' ' * (len(_type) + 2), endpoint['pid'],
                                                              (endpoint['name'][:52] + '...') if endpoint['name'][
                                                                                                 55:] else
                                                              endpoint['name'].strip(), endpoint['fd'])
        elif _type in namespaces:
            # permissions, file flags and identities should not matter
            result = "namespace: type {} inode {}".format(_type, value)
        else:
            raise Exception("Unexpected pseudo file type " + _type)
        return result

    @staticmethod
    def getFdFromEndpointDict(endpoints, pid):
        """
        This functions takes an array of endpoint describing dictionaries (for pipes & sockets) and return the matching
        file descriptor for a pid.
        :param pid: The pid to search for.
        :param endpoints: The data to search in.
        :return: The file descriptor number on success, none otherwise
        """
        for epdata in endpoints:
            if epdata['pid'] == pid:
                return epdata['fd']

        return None

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
                    props = self.getSocketProperties(inode_entry)
                    if props:
                        st_mode = props['st_mode']
                        # permissions = file_mode.getModeString(st_mode)
                        permissions = format(st_mode & 0x01FF, 'o')
                    else:
                        permissions = "unknown"
                    inode_entry = "{} (file permissions: {})".format(
                        inode_entry, permissions
                    )

                result.append("{}:{}".format(transport_protocol, inode_entry))
            elif transport_protocol == "netlink":
                result.append("netlink socket {} type:'{}'"
                              .format(inode, Netlink.resolveNetlinkSubprotocolToHumanName(inode_entry)))
            elif transport_protocol == "packet":
                packet = PacketSocket.FromTuple(inode_entry)
                result.append(str(packet))
            else:  # TCP or UDP socket with IP address and port
                sc = NetworkSocket.fromTuple(inode_entry, transport_protocol)
                res = "{}".format(str(sc))

                nwiface_wrapper = self.m_daw_factory.getNwIfaceInfoWrapper()
                data = nwiface_wrapper.getAllNwIfaceData()
                nwiface = sc.getNwIface(data)

                if nwiface:
                       res = "{} if {}".format(str(sc), nwiface)
                result.append(res)
                logging.debug(res)

        result = "|".join(result)

        if result:
            return result
        else:
            return "<unknown protocol/no information for {}>".format(inode)

    def getFileProperties(self, filename):
        """Returns the properties of a given file path in the file system. Or
        an empty dictionary on failure."""
        fs_wrapper = self.m_daw_factory.getFsWrapper()

        return fs_wrapper.getFileProperties(filename)

    def getSocketProperties(self, filename):
        """Returns the properties of a given file path in the file system. Or
        an empty dictionary on failure."""
        fs_wrapper = self.m_daw_factory.getFsWrapper()

        return fs_wrapper.getSocketProperties(filename)

    def __str__(self):
        return self.toString()

    def toString(self, verbose=False):

        flags = file_mode.getFdFlagLabels(self.m_info["file_flags"])
        file_perm = {
            "Uid": (self.m_info["file_perm"] & stat.S_IRWXU) >> 6,
            "Gid": (self.m_info["file_perm"] & stat.S_IRWXG) >> 3,
            "other": (self.m_info["file_perm"] & stat.S_IRWXO) >> 0,
        }

        # pseudo files: sockets, pipes, ...
        if self.is_pseudo_file:

            line = self.getPseudoFileDesc(self.symlink)

            if verbose:
                line = "{:>5}: ".format(self.m_socket) + line
            if type == "socket":
                line = "{} {}".format(line, file_mode.getModeString(self.m_info["file_perm"]))
            if flags:
                # the flags need to be appended to the end of the first line. Pipes i.e. with their connection can span
                # multiple lines, but having the flag after the last connection is confusing.
                lines = line.split("\n", 2)
                lines[0] = "{} w/ {}".format(lines[0], "|".join(flags))
                line = "\n".join(lines)

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

            line = self.symlink
            # if color_it:
            #     line = self.getColored(line)

            if verbose:
                line = "{:>5}: ".format(self.m_socket.fd) + line
            line = "{} {} {}:{}".format(line, file_mode.getModeString(self.m_info["file_perm"]),
                                        self.m_account_wrapper.getNameForUid(self.m_uid[0]),
                                        self.m_account_wrapper.getNameForGid(self.m_gid[0]))

            if flags:
                line = "{} w/ {}".format(line, "|".join(flags))

            line = "{} [fd: {}]".format(line, self.fd_number)

            return line


class PacketSocket(object):
    """This class represents a packet socket (/proc/*/net/packet)."""

    TYPES = {  # from bits/socket_type.h
        2: 'COOKED',
        3: 'RAW'
    }

    def __init__(self, type, iface, inode, ifaceResolver=None):
        """
        Create a new instance of PacketSocket
        :param type: The type of the socket.
        :param iface: The interface number.
        :param inode: The inode number.
        :param ifaceResolver: A lambda which resolves the interface number to an interface name. Can be None.
        """
        self.m_type = type
        self.m_iface = iface
        self.m_inode = inode
        self.m_iface_name = str(ifaceResolver(iface)) if ifaceResolver is not None else str(iface)

    def getSocketTypeStr(self):
        """Return the type of the socket as string"""
        return self.TYPES[self.m_type] if self.m_type in self.TYPES else '[UNKNOWN TYPE]'

    def __str__(self):
        return 'packet {} {} on interface {}'.format(self.m_inode, self.getSocketTypeStr(), self.m_iface_name)

    @staticmethod
    def FromTuple(inode_entry, ifaceResolver=None):
        return PacketSocket(inode_entry[2], inode_entry[4], inode_entry[-1], ifaceResolver)


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
        elif self.m_protocol == 'tcp':  # only tcp has a listening state
            outp += ' listening/waiting'
        return outp

    def getNwIface(self, data):
        return self.m_local_endpoint.getNwIface(data)


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

    def getNwIface(self, data):
        """
        tries to match an ip address from an interface with the
        network endpoint's ip address
        :dictionary data: the collected interface data
        """
        for iface in data:
            if self.m_ip_version == 4 and 'ipv4' in data[iface]:
                if data[iface]['ipv4'][0].split('/')[0] == str(
                        self).split(':')[0]:
                    return iface
            elif self.m_ip_version == 6 and 'ipv6' in data[iface]:
                if self.IPv6ToString(
                        data[iface]['ipv6'][0]
                        ).split('.')[0] == str(self).split(']')[0][1:]:
                    return iface
        return ""

    def __str__(self):
        if self.m_ip_version == 4:
            return '{}:{}'.format(socket.inet_ntoa(struct.pack('<L', int(self.m_ip, 16))), str(self.m_port))
        else:
            return '[{}]:{}'.format(self.IPv6ToString(self.m_ip), str(self.m_port))

class Netlink(object):
    """This class provides some information related to netlink sockets."""

    # as found in /usr/include/linux/netlink.h
    NETLINK_SUBPROTOCOLS = {
        0: 'NETLINK_ROUTE',
        1: 'NETLINK_UNUSED',
        2: 'NETLINK_USERSOCK',
        3: 'NETLINK_FIREWALL',
        4: 'NETLINK_SOCK_DIAG',
        5: 'NETLINK_NFLOG',
        6: 'NETLINK_XFRM',
        7: 'NETLINK_SELINUX',
        8: 'NETLINK_ISCSI',
        9: 'NETLINK_AUDIT',
        10: 'NETLINK_FIB_LOOKUP',
        11: 'NETLINK_CONNECTOR',
        12: 'NETLINK_NETFILTER',
        13: 'NETLINK_IP6_FW',
        14: 'NETLINK_DNRTMSG',
        15: 'NETLINK_KOBJECT_UEVENT',
        16: 'NETLINK_GENERIC'
    }

    @staticmethod
    def resolveNetlinkSubprotocolToName(protoid):
        """
        Returns the name of a netlink subprotocol.
        :param protoid: The id of the subprotocol.
        :return: The name of the subprotocol.
        """
        return Netlink.NETLINK_SUBPROTOCOLS[int(protoid)]

    @staticmethod
    def resolveNetlinkSubprotocolToHumanName(protoid):
        """
        Returns the name of a netlink subprotocol without the 'NETLINK_' prefix.
        :param protoid: The id of the subprotocol.
        :return: The name of the subprotocol without the 'NETLINK_' prefix.
        """
        return Netlink.resolveNetlinkSubprotocolToName(protoid).replace('NETLINK_', '')
