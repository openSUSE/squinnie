#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# security scanner - scan a system's security related information
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

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
import sys
import argparse
import copy
import re
import os

# Local modules
import sscanner.dumper
import sscanner.crowbar
import sscanner.errors
import sscanner.viewer
from sscanner.types import Modes

class SecurityScanner(object):
    """main class that implements this command-line utility."""

    def __init__(self):

        self.m_discard_data = False
        self.setupParser()

    def setupParser(self):

        description = "Main security scanner tool. Collect and display security data of local and remote hosts."
        parser = argparse.ArgumentParser(description=description)

        # General
        general_group = parser.add_argument_group('general arguments')

        description = "The directory all files are cached in. If not specified, a temporary directory will be used to save files during the execution of the script and then deleted at the end."
        general_group.add_argument("-d", "--directory", type=str, help=description)

        description = "Print more detailed information."
        general_group.add_argument("-v", "--verbose", action="store_true", help=description)

        # description = "List all nodes in the network."
        # general_group.add_argument("-l", "--list", action="store_true", help=description)

        description = "When using a mode that scans multiple hosts, print information from all nodes. By default, only the entry node is printed."
        general_group.add_argument("-a", "--all", action="store_true", help=description)

        # Dump
        dump_group = parser.add_argument_group('scan / dump arguments')

        description = "The mode the scanner should be operating under. 'local' by default"
        dump_group.add_argument("-m", "--mode", type=Modes.checkModeArg, help=description, default="local")

        description = "The first hop scan host. The only target host for mode == 'ssh', the crowbar host for mode == 'susecloud'"
        dump_group.add_argument("-e", "--entry", type=str, help=description)

        description = "Path to the JSON network configuration file for scanning (for mode =='crowbar'). Will be generated here if not already existing."
        dump_group.add_argument("-n", "--network", type=str, help=description,
                default = "etc/network.json"
        )

        description = "Ignore and remove any cached files, forcing a fresh scan."
        dump_group.add_argument("--nocache", action="store_true", help=description)

        view_group = parser.add_argument_group('view arguments')
        # definitions come from the viewer module itself
        sscanner.viewer.Viewer.add_parser_arguments(view_group)

        self.m_parser = parser

    def _checkDirectoryArg(self):

        self.m_discard_data = False

        if not self.m_args.directory:
            import tempfile
            self.m_args.directory = tempfile.mkdtemp(prefix = "cloud_scanner")
            self.m_discard_data = True
            print("Storing temporary data in", self.m_args.directory)
        elif not os.path.isdir(self.m_args.directory):
            os.makedirs(self.m_args.directory)

    def _checkModeArgs(self):

        if self.m_args.mode in (Modes.susecloud, Modes.ssh):

            if not self.m_args.entry:
                raise sscanner.errors.ScannerError(
                    "For susecloud and ssh mode the --entry argument is requried"
                )

    def _collectDumps(self):
        """Collects the node dumps according to the selected mode and cached
        data use. The result is stored in self.m_node_data"""

        if self.m_args.mode == Modes.susecloud:
            dumper = sscanner.dumper.SshDumper()
            nwconfig_path = self.m_args.network

            if not os.path.isabs(nwconfig_path):
                nwconfig_path = os.path.realpath(nwconfig_path)

            # crowbar module arguments
            crowbar = sscanner.crowbar.Crowbar()
            crowbar.set_entry_node(self.m_args.entry)
            crowbar.set_use_cache(not self.m_args.nocache)
            crowbar.set_config_path(nwconfig_path)

            nwconfig = crowbar.load_network_info()
            dumper.set_network_config(crowbar.get_network_info())
        elif self.m_args.mode == Modes.ssh:
            dumper = sscanner.dumper.SshDumper()
            dumper.set_network_config({self.m_args.entry: []})
        elif self.m_args.mode == Modes.local:
            dumper = sscanner.dumper.LocalDumper()

        dumper.set_output_dir(self.m_args.directory)
        dumper.set_use_cache(not self.m_args.nocache)
        dumper.collect(load_cached = True)

        self.m_node_data = dumper.get_node_data()
        dumper.save()
        dumper.print_cached_dumps()

    def _viewData(self):
        """Performs the view operation according to command line parameters.
        The node data needs to have been collected for this to work."""

        viewer = sscanner.viewer.Viewer()
        viewer.activate_settings(self.m_args)

        if self.m_args.mode in (Modes.local, Modes.ssh):
            self.m_args.all = True

        # iterate over only the single node or all nodes depending on mode and
        # command line switches
        nodes = self.m_node_data if self.m_args.all else [ self.m_node_data[0] ]

        for config in self.m_node_data:
            print("\n\nReport for {} ...".format(config['node']))
            viewer.set_data(config['node'], config['data'])
            viewer.perform_action(self.m_args)

    def _cleanupData(self):
        import shutil
        if self.m_args.verbose:
            print("Removing temporary data in", self.m_args.directory)
        shutil.rmtree(self.m_args.directory)

    def run(self):
        try:
            self.m_args = self.m_parser.parse_args()
            self._checkDirectoryArg()
            self._checkModeArgs()

            self._collectDumps()
            self._viewData()
        finally:
            if self.m_discard_data:
                self._cleanupData()

if __name__ == "__main__":

    scanner = SecurityScanner()
    sscanner.helper.executeMain(scanner.run)

