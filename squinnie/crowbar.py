#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Squinnie - scan a system's security related information

# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author:     Benjamin Deuter
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
from __future__ import print_function
from __future__ import with_statement
import argparse
import sys
import os

# foreign modules
import termcolor

# Local modules
import squinnie.helper
import squinnie.network_config
import squinnie.errors
import logging

# PyPy modules
try:
    import execnet
except ImportError:
    squinnie.helper.missingModule("execnet")

class Crowbar(object):
    """This class can collect the crowbar network configuration from a SUSE
    cloud master node and store it as a network_config file.
    """

    def __init__(self):

        self.m_use_cache = True
        self.m_config_path = None
        self.m_entry_node = None
        self.m_net_config = squinnie.network_config.NetworkConfig()
        self.m_info = {}

    def setUseCache(self, cache):

        self.m_use_cache = cache

    def setConfigPath(self, path):
        self.m_config_path = path

    def setEntryNode(self, node):
        """Set the hostname or IP of the crowbar entry node for scanning the
        network configuration.
        """
        self.m_entry_node = node

    def getNetworkInfo(self):
        """Returns the currently loaded network info. Only valid if
        loadNetworkInfo() was successfully called.
        """
        return self.m_info

    def getCrowbarConfig(self):
        """
        Creates a connection to the configured entry node and retrieves a
        machine listing from crowbar running there.

        Returns a dictionary of the form {
            "entry": ["machine1", "machine2", ...]
        }
        """
        if not self.m_entry_node:
            raise squinnie.errors.ScannerError("entry node for scanning crowbar network is required")

        group = execnet.Group()
        master = group.makegateway(
            "id=master//python=python{}//ssh=root@{}".format(2, self.m_entry_node)
        )

        cmd = "crowbar machines list"
        exec_cmd = """
            import subprocess
            channel.send(subprocess.check_output('{}'))
        """.format(cmd)
        try:
            crowbar_output = master.remote_exec(exec_cmd).receive()
        except execnet.RemoteError as e:
            raise squinnie.errors.ScannerError("Failed to run crowbar on {}:\n\n{}".format(
                self.m_entry_node, e
            ))

        node_lines = crowbar_output.splitlines()

        # filter out empty lines
        node_lines = list(filter(None, node_lines))
        try:
            node_lines.remove(self.m_entry_node)
        except ValueError:
            raise squinnie.errors.ScannerError("entry node was not found in returned crowbar data")

        return {
            self.m_entry_node: [str(item) for item in node_lines]
        }

    def loadNetworkInfo(self):
        """Retrieve the crowbar network data for the configured entry node. If
        a config file exists on disk it will be used (if cache is enabled),
        otherwise data from the remote host will be collected and saved to
        disk.

        The obtained data will be saved in the object and can be obtained via
        getNetworkInfo().
        """
        if self._haveCache():
            self._loadConfig()
        else:
            self._fetchConfig()

    def _loadConfig(self):
        logging.info("Using cached crowbar network data from {}".format(self.m_config_path))
        self.m_net_config.load(self.m_config_path)
        self.m_info = self.m_net_config.getNetwork()

    def _fetchConfig(self):
        self.m_info = self.getCrowbarConfig()
        self.m_net_config.setNetwork(self.m_info)
        self.m_net_config.save(self.m_config_path)
        logging.info("Wrote crowbar network data to {}\n".format(self.m_config_path))

    def _haveCache(self):

        if not self.m_use_cache:
            return False

        return self.m_config_path and os.path.isfile(self.m_config_path)
