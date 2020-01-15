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
from squinnie.daw.helper import CategoryLoader
from squinnie.daw.sockets import FdWrapper
import logging


class ProcessData(object):

    def __init__(self, dumpIO, factory):
        """
        :param dumpIO: An instance of squinnie.dio.DumpIO for loading the data
        """
        self.m_dumpIO = dumpIO
        self.m_data = {}
        self.m_ll_proc = CategoryLoader("proc_data", self.m_dumpIO)
        # self.m_ll_children = CategoryLoader("children", self.m_dumpIO)
        self.m_ll_parents = CategoryLoader("parents", self.m_dumpIO)
        self.m_daw_factory = factory
        self.m_socket_connection_cache = SocketCache()
        self.m_shm_cache = ShmCache()

    def getProcData(self):
        """Return general process data."""
        return self.m_ll_proc.getData()

    def getParents(self):
        """Return the parents of each process"""
        return self.m_ll_parents.getData()

    # def getChildren(self):
    #     """Return the children of each process"""
    #     return self.m_ll_children.getData()

    def getProcessCount(self):
        """Returns the number of recorded processes for the scanned host"""
        return len(self.getProcData())

    def getAllPids(self):
        """Returns all process ids found on the scanned host"""
        return self.getProcData().keys()

    def getProcessInfo(self, pid):
        """Get the data for a specific process"""
        return self.getProcData()[pid]

    def processHasUid(self, pid, uid):
        """This method checks whether a process contains the given UID."""
        return uid in self.getProcData()[pid]["Uid"]

    def processHasGid(self, pid, gid):
        """This method checks whether a process contains the given GID."""
        return gid in self.getProcData()[pid]["Gid"]

    def getChildrenForPid(self, searched_pid):
        """Returns all children for a given pid."""
        return [pid for pid, parent in self.getParents().items() if searched_pid == parent]

    def getFileDescriptorsForPid(self, pid):
        """Returns an instance of FileHandlerWrapper for a given process."""
        data = self.getProcessInfo(pid)
        return FdWrapper(pid, data['open_files'], data['Uid'], data['Gid'], self.m_daw_factory)

    def getEndpointsForPipe(self, id):
        """Returns the endpoints for a pipe."""
        self.m_socket_connection_cache.buildIfNecessary(self.getProcData)
        return self.m_socket_connection_cache.getEndpointsForPipe(id)

    def getEndpointsForSocket(self, id):
        """Returns the endpoints for a socket."""
        self.m_socket_connection_cache.buildIfNecessary(self.getProcData)
        return self.m_socket_connection_cache.getEndpointsForSocket(id)

    def getEndpointsForQueue(self, id):
        """Returns the endpoints for a queue."""
        self.m_socket_connection_cache.buildIfNecessary(self.getProcData)
        return self.m_socket_connection_cache.getEndpointsForQueue(id)

    def getOtherPointOfPipe(self, pipe_id, pid):
        """Returns the first endpoint of a pipe which does not have the given pid."""
        self.m_socket_connection_cache.buildIfNecessary(self.getProcData)
        return self.m_socket_connection_cache.getOtherPointOfPipe(pipe_id, pid)

    def getThreadsForPid(self, pid):
        return self.getProcData()[pid]['threads']

    def getRuntimeOfProcess(self, pid):
        return self.m_daw_factory.getSystemDataWrapper().getProcessUptime(self.getProcessInfo(pid)['starttime'])

    def getShmsForPid(self, pid):
        """
        Returns all shm entries a pid has.
        :param pid: The pid to search for.
        :return:
        """
        self.m_shm_cache.buildIfNecessary(self.getProcData,
                                          lambda: self.m_daw_factory.getSystemDataWrapper().getShmData())
        return self.m_shm_cache.getShmsForPid(pid)


class SocketCache:
    """This class saves the connection endpoints for all pipes and sockets."""

    def __init__(self):
        self.m_pipes = None
        self.m_sockets = None
        self.m_queues = None

    def isBuilt(self):
        return self.m_pipes is not None

    def buildIfNecessary(self, data_source):
        """Build the cache if necessary. data_source must be a lambda that supplies the data."""
        if not self.isBuilt():
            self.build(data_source())

    def build(self, data):
        """Build the cache. The data should be the proc data."""
        self.m_pipes = {}
        self.m_sockets = {}
        self.m_queues = {}
        logging.debug('Building pipe cache.')

        # loop each process
        for pid, process_data in data.items():
            fds = process_data['open_files']

            # check for each file descriptor
            for fd, fd_info in fds.items():

                # only pipes are of interest in this case
                if self.isPipe(fd_info):
                    id = SocketCache.extractInodeFromFdInfo(fd_info)

                    if id not in self.m_pipes:
                        self.m_pipes[id] = []

                    self.m_pipes[id].append({
                        'pid': pid,
                        'name': '{} {}'.format(process_data['executable'], process_data['parameters']),
                        'fd': fd
                    })
                elif self.isSocket(fd_info):
                    id = SocketCache.extractInodeFromFdInfo(fd_info)

                    if id not in self.m_sockets:
                        self.m_sockets[id] = []

                    self.m_sockets[id].append({
                        'pid': pid,
                        'name': '{} {}'.format(process_data['executable'], process_data['parameters']),
                        'fd': fd
                    })
                elif 'queue' in fd_info:
                    queue = fd_info['queue']

                    if queue not in self.m_queues:
                        self.m_queues[queue] = []

                    self.m_queues[queue].append({
                        'pid': pid,
                        'name': '{} {}'.format(process_data['executable'], process_data['parameters']),
                        'fd': fd
                    })


    @staticmethod
    def extractInodeFromFdInfo(fd_info):
        """Extracts the inode of a socket from the fdinfo tuple."""
        return SocketCache.extractInodeFromSymlink(fd_info['symlink'])

    @staticmethod
    def extractInodeFromSymlink(target):
        """Extracts the inode of a socket from the link target as seen in /proc/*/fd."""
        return int(target.split(':', 1)[1].strip('[]'))

    @staticmethod
    def isPipe(fdinfo):
        """Checks whether the file descriptor is a pipe from the proc data set."""
        descr = fdinfo["symlink"]
        return SocketCache.isInodeSocketWithName(descr, 'pipe')

    @staticmethod
    def isSocket(fdinfo):
        """Returns whether a filedescriptor from /proc/*/fd is a socket."""
        descr = fdinfo["symlink"]
        return SocketCache.isInodeSocketWithName(descr, 'socket')

    @staticmethod
    def isInodeSocketWithName(link, socket_name):
        """
        Returns whether this is a socket with an inode and a specific name.
        :param link: The link target (from proc) to parse.
        :param socket_name: The searched socket name.
        :return:
        """
        # the value in symlink we search for is "pipe:1234", compared to i.e. '/var/lib/socket' or 'unix:123'
        return (not link.startswith('/')) and link.split(':', 1)[0].strip("[]") == socket_name

    def getEndpointsForPipe(self, id):
        """Returns the endpoints for a pipe."""
        return self.m_pipes[int(id)]

    def getOtherPointOfPipe(self, pipe_id, pid):
        """Returns the first endpoint of a pipe which does not have the given pid."""
        for endpoint in self.getEndpointsForPipe(pipe_id):
            if not endpoint['pid'] == pid:
                return endpoint
        return None

    def getEndpointsForSocket(self, id):
        """Returns the endpoints for a sockets."""
        return self.m_sockets[int(id)]

    def getEndpointsForQueue(self, id):
        """Returns the endpoints for a queue."""
        return self.m_queues[id]


class ShmCache:
    """This class saves the connection endpoints for all pipes and sockets."""

    def __init__(self):
        self.m_shm = None

    def isBuilt(self):
        return self.m_shm is not None

    def buildIfNecessary(self, proc_source, shm_source):
        """Build the cache if necessary. data_source must be a lambda that supplies the data."""
        if not self.isBuilt():
            self.build(proc_source(), shm_source())

    def build(self, procdata, shmdata):
        """Build the cache. The data should be the proc data."""
        self.m_shm = dict([(int(data['inode']), {
            'name': data['name'],
            'inode': data['inode'],
            'pids': {}
        }) for data in shmdata])
        logging.debug('Building shm cache.')

        for pid, process_data in procdata.items():
            for map in process_data['maps']:
                if int(map['inode']) in self.m_shm:
                    self.m_shm[int(map['inode'])]['pids'][pid] = {
                        'pid': pid,
                        'name': '{} {}'.format(process_data['executable'], process_data['parameters']),
                    }

    def getShmsForPid(self, pid):
        """
        Returns all shm entries a pid has.
        :param pid: The pid to search for.
        :return:
        """
        return dict([(inode, shm) for inode, shm in self.m_shm.items() if (pid in shm['pids'])])
