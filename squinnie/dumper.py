#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Squinnie - scan a system's security related information

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

# Standard library modules.
from __future__ import with_statement
from collections import OrderedDict
import logging
import sys
import os

# local modules
import squinnie.helper
import squinnie.probe
import squinnie.network_config
from squinnie.dio import DumpIO
from squinnie.errors import ScannerError

# foreign modules
try:
    import execnet
    import termcolor
except ImportError as e:
    squinnie.helper.missingModule(ex=e)


class Dumper(object):
    """This class is able to collect the node data from local or remote hosts
    and stores and loads the data from dump files on disk as required. It
    needs to be specialized to actually work.

    By contract a collect() method needs to be implemented like done in
    SshDumper and LocalDumper.
    """

    def __init__(self):

        self.m_outdir = None
        self.m_use_cache = True

    def setUseCache(self, use):
        self.m_use_cache = use

    def setOutputDir(self, path):
        self.m_outdir = path

    def printCachedDumps(self):
        """Prints an informational line for each dump that was not freshly
        collected due to caching.
        """
        if not self.m_use_cache:
            return

        for node in self.getNodeData():
            if node['cached']:
                logging.info("Not regenerating cached dump for %s" % node['node'])

    def getNodeData(self):
        """Returns the currently collected node data. Only valid after a call
        to collect(). The returned data is a list of dictionaries describing
        each individual node dump.
        """
        return self.m_nodes

    def save(self):
        """Save collected node dumps in their respective dump files, if
        they're not cached.
        """
        for config in self.m_nodes:
            if config['cached']:
                continue

            node_data_dict = {
                config['node']: config['data']
            }
            dump_path = config['full_path']

            dio = DumpIO(config["node"], path=self.m_outdir)
            dio.saveFullDump(node_data_dict[config["node"]])

    def _getFilename(self, node_str):
        # apparently .p is commonly used for pickled data
        file_extension = "p"
        return "{}.{}".format(node_str.replace(".", "-"), file_extension)

    def _getFullDumpPath(self, dump):
        return os.path.join(self.m_outdir, dump)

    def _haveCachedDump(self, key):
        dio = DumpIO(key, path=self.m_outdir)
        return dio.hasCache()

    def _discardCachedDumps(self):
        """Discards any cached dump files for the nodes currently setup in
        self.m_nodes
        """
        for config in self.m_nodes:

            if config['cached']:
                dio = DumpIO(config["node"], path=self.m_outdir)
                dio.clearCache()
                config['cached'] = False

    def _loadCachedDumps(self):
        """Loads any dumps for nodes in self.m_nodes that are marked as cached
        from their respective dump file paths.
        """
        for config in self.m_nodes:

            if not config['cached'] or 'data' in config:
                continue
            dump_path = config['full_path']

            logging.info("Loading cached dump from %s" % str(dump_path))

            dmp = DumpIO(config['node'], path=self.m_outdir)

            # no need to load the full dumps anymore since everything should use the daw
            # config['data'] = dmp.loadFullDump()

    def _setupDumpNodes(self, node_list):
        """Stores a list in self.m_nodes containing dictionaries describing
        the nodes and their respective dump paths for future operations.
        """
        self.m_nodes = []

        for node, parent in node_list:
            dump = self._getFilename(node)

            self.m_nodes.append({
                "node": node,
                "path": dump,
                "full_path": self._getFullDumpPath(dump),
                "via": parent,
                "cached": self._haveCachedDump(node)
            })


class SshDumper(Dumper):
    """A specialized dumper that collects data from a remote host."""

    def __init__(self, *args, **kwargs):
        super(SshDumper, self).__init__(*args, **kwargs)
        self.m_network = None

    def setNetworkConfig(self, nc):
        """Set an already existing network configuration dictionary for futher
        use during collect().
        """
        self.m_network = nc
        import pprint
        logging.debug("been set network network: {}".format(pprint.pformat(nc)))

    def loadNetworkConfig(self, file_name):
        """Reads the target network configuration from the given JSON file and
        stores it in the object for further use during collect().
        """
        self.m_network = squinnie.network_config.NetworkConfig().load(file_name)
        import pprint
        logging.debug("Parsing network: {}".format(pprint.pformat(self.m_network)))

    def collect(self, load_cached):
        """Collect data from the configured remote host, possibly further
        hosts depending on the active network configuration.

        You can retrieve the collected data via getNodeData() after a
        successful call to this function.

        :param bool load_cached: if set then cached dumps that already exist
        on disk will also be loaded
        """
        if not self.m_network or not self.m_outdir:
            raise ScannerError("Missing network and/or output directory")

        node_list = self._getNetworkNodes()
        self._setupDumpNodes(node_list)

        if not self.m_use_cache:
            self._discardCachedDumps()

        self._receiveData()
        if load_cached:
            self._loadCachedDumps()

    def _getNetworkNodes(self):
        """Flattens the nodes found in self.m_network and returns them as a
        list of (node, parent), where parent is an optional jump host to reach
        the node.
        """
        ret = []
        for hop, network in self.m_network.items():
            ret.append((hop, None))
            ret.extend([(node, hop) for node in network])

        return ret

    def _getExecnetGateway(self, node, via):
        """Returns a configuration string for execnet's makegatway() function
        for dumping the given node.
        """
        data = {
            "ssh": "root@{}".format(node) if "@" not in node else node,
            "id": "{}".format(node),
            "python": "python{}".format(2)
        }

        if via:
            data["via"] = via

        parts = ["{}={}".format(key, value) for key, value in data.items()]

        return "//".join(parts)

    def _receiveData(self):

        group = execnet.Group()
        data = {}

        for config in self.m_nodes:
            if config['cached']:
                continue
            node = config['node']
            logging.info("Receiving data from {}".format(node))
            gateway = self._getExecnetGateway(node, config['via'])
            try:
                group.makegateway(gateway)
            except execnet.HostNotFound as e:
                raise ScannerError("Failed to connect to remote host: " + str(e))

            config['data'] = group[node].remote_exec(squinnie.probe).receive()


class LocalDumper(Dumper):
    """A specialized dumper that collects data from the local host."""

    def __init__(self, *args, **kwargs):
        super(LocalDumper, self).__init__(*args, **kwargs)

    def collect(self, load_cached):
        """See SshDumper.collect(), only this variant will only collect from
        the localhost, possibly involving a call to 'sudo' if root permissions
        are missing.
        """
        if not self.m_outdir:
            raise ScannerError("Missing output directory")

        node_list = self._getLocalNode()
        self._setupDumpNodes(node_list)

        if not self.m_use_cache:
            self._discardCachedDumps()
        elif self.m_nodes[0]['cached']:
            if load_cached:
                self._loadCachedDumps()
            # nothing to do
            return

        have_root_privs = os.geteuid() == 0

        # might be a future command line option to allow running as non-root. could be helpful for testing
        # print("You're scanning as non-root, only partial data will be collected")
        # print("Run as root to get a full result. This mode is not fully supported.")
        node_data = self._subprocessCollect(use_sudo=not have_root_privs)
        self.m_nodes[0]['data'] = node_data

    def _getLocalNode(self):
        """Returns a node list containing just the localhost for local
        dumping.
        """
        import socket
        node = socket.gethostname()
        return [(node, None)]

    def _subprocessCollect(self, use_sudo=True):
        """
        calls the standalone scanning script as subprocess
        :return: node-data from Pickle
        """
        import subprocess

        # gzip has a bug in python2, it can't stream, because it tries
        # to seek *sigh*
        use_pipe = squinnie.helper.isPython3()

        if not use_pipe:
            import tempfile
            tmpfile = tempfile.TemporaryFile(mode='wb+')

        prefix = ['sudo'] if use_sudo else []

        slave_proc = subprocess.Popen(
            prefix +
            [
                # use the same python interpreter as we're currently
                # running
                sys.executable,
                os.path.join(
                    os.path.dirname(__file__),
                    "probe.py"
                )
            ],
            stdout=subprocess.PIPE if use_pipe else tmpfile,
            close_fds=True
        )

        if use_pipe:
            try:
                node_data = squinnie.helper.readPickle(fileobj=slave_proc.stdout)
            finally:
                if slave_proc.wait() != 0:
                    raise Exception("Failed to run probe.py")
        else:
            try:
                if slave_proc.wait() != 0:
                    raise Exception("Failed to run probe.py")
                tmpfile.seek(0)
                node_data = squinnie.helper.readPickle(fileobj=tmpfile)
            finally:
                tmpfile.close()

        return node_data
