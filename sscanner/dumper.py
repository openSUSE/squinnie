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

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
from collections import OrderedDict
import argparse
import sys
import os

# local modules
import helper
import slave
import enrich
import network_config

# foreign modules
try:
    import execnet
    import termcolor
except ImportError as e:
    helper.missingModule(ex = e)

class Dumper(object):
    """This class is able to collect the node data from local or remote hosts
    and stores and loads the data from dump files on disk as required."""

    def __init__(self):

        self.m_network = None
        self.m_outdir = None
        self.m_use_cache = True

    def set_use_cache(self, use):
        self.m_use_cache = use

    def set_output_dir(self, path):
        self.m_outdir = path

    def print_cached_dumps(self):
        """Prints an informational line for each dump that was not freshly
        collected due to caching."""
        if not self.m_use_cache:
            return

        for node in self.get_node_data():
            if node['cached']:
                print("Not regenerating cached dump for", node['node'])

    def load_network_config(self, file_name):
        """Reads the target network configuration from the given JSON file and
        stores it in the object for further use during collect()."""
        self.m_network = network_config.NetworkConfig().load(file_name)

    def set_network_config(self, nc):
        """Set an already existing network configuration dictionary for futher
        use during collect()."""
        self.m_network = nc

    def get_node_data(self):
        """Returns the currently collected node data. Only valid after a call
        to collect()."""
        return self.m_nodes

    def collect(self, load_cached):
        if not self.m_network or not self.m_outdir:
            raise Exception("Missing network and/or output directory")

        node_list = self._get_network_nodes()
        self._setup_dump_nodes(node_list)

        if not self.m_use_cache:
            self._discard_cached_dumps()

        self._receive_data()
        if load_cached:
            self._load_cached_dumps()

    # TODO: separating the local and remote scan into different class
    # specializations would be way cleaner
    def collect_local(self, load_cached):

        if not self.m_outdir:
            raise Exception("Missing output directory")

        node_list = self._get_local_node()
        self._setup_dump_nodes(node_list)

        if not self.m_use_cache:
            self._discard_cached_dumps()
        elif self.m_nodes[0]['cached']:
            # nothing to do
            return

        have_root_privs = os.geteuid() == 0

        if have_root_privs:
            node_data = slave.collect()
            self.m_nodes[0]['data'] = node_data
        else:
            # might be a future command line option to allow this, is helpful
            # for testing. For now we use sudo.
            #print("You're scanning as non-root, only partial data will be collected")
            #print("Run as root to get a full result. This mode is not fully supported.")
            node_data = self._sudo_collect()
            self.m_nodes[0]['data'] = node_data

    def _sudo_collect(self):
        import subprocess

        # gzip has a bug in python2, it can't stream, because it tries
        # to seek *sigh*
        use_pipe = helper.isPython3()

        if not use_pipe:
            import tempfile
            tmpfile = tempfile.TemporaryFile(mode = 'wb+')

        slave_proc = subprocess.Popen(
            [
                "sudo",
                # use the same python interpreter as we're currently
                # running
                sys.executable,
                os.path.join(
                    os.path.dirname(__file__),
                    "slave.py"
                )
            ],
            stdout = subprocess.PIPE if use_pipe else tmpfile,
            close_fds = True
        )

        if use_pipe:
            try:
                node_data = helper.readPickle(fileobj = slave_proc.stdout)
            finally:
                if slave_proc.wait() != 0:
                    raise Exception("Failed to run slave.py")
        else:
            try:
                if slave_proc.wait() != 0:
                    raise Exception("Failed to run slave.py")
                tmpfile.seek(0)
                node_data = helper.readPickle(fileobj = tmpfile)
            finally:
                tmpfile.close()

        return node_data

    def save(self):
        """Save collected node dumps in their respective dump files, if
        they're not cached."""
        for config in self.m_nodes:
            if config['cached']:
                continue

            node_data_dict = {
                    config['node']: config['data']
            }
            enricher = enrich.Enricher(node_data_dict)
            print("Enriching node data")
            enricher.enrich()
            dump_path = config['full_path']
            print("Saving data to {}".format(dump_path))
            enricher.save_data(dump_path)

    def _get_network_nodes(self):
        """Flattens the nodes found in self.m_network and returns them as a
        list of (node, parent), where parent is an optional jump host to reach
        the node."""

        ret = []

        def gather_nodes(lst, data, parent = None):

            if type(data) in (OrderedDict,dict):
                for key, val in data.items():
                    lst.append((key,None))
                    gather_nodes(lst, val, key)
            elif type(data) is list:
                ret.extend( [ (node, parent) for node in data ] )
            else:
                raise Exception("Bad network description data, unexpected type "
                    + str(type(data)))

            return ret

        gather_nodes(ret, self.m_network)

        return ret

    def _get_local_node(self):
        """Returns a node list containing just the localhost for local
        dumping."""
        import socket
        node = socket.gethostname()
        return [(node, None)]

    def _get_filename(self, node_str):
        # apparently .p is commonly used for pickled data
        file_extension = "p"
        return "{}.{}".format(node_str.replace(".", "-"), file_extension)


    def _get_full_dump_path(self, dump):
        return os.path.join(self.m_outdir, dump)

    def _have_cached_dump(self, dump):
        return os.path.isfile( self._get_full_dump_path(dump) )

    def _discard_cached_dumps(self):
        """Discards any cached dump files for the nodes currently setup in
        self.m_nodes"""

        for config in self.m_nodes:

            if config['cached']:
                print("Discarding cached data for", config['node'])
                os.remove(config['full_path'])
                config['cached'] = False

    def _load_cached_dumps(self):
        """Loads any dumps for nodes in self.m_nodes that are marked as cached
        from their respective dump file paths."""

        for config in self.m_nodes:

            if not config['cached'] or 'data' in config:
                continue
            dump_path = config['full_path']

            print("Loading cached dump from", dump_path)
            data = helper.readPickle( path = dump_path )
            config['data'] = data.values()[0]

    def _setup_dump_nodes(self, node_list):
        """Stores a list in self.m_nodes containing dictionaries describing
        the nodes and their respective dump paths for future operations.
        """

        self.m_nodes = []

        for node, parent in node_list:

            dump = self._get_filename(node)

            self.m_nodes.append( {
                "node": node,
                "path": dump,
                "full_path": self._get_full_dump_path(dump),
                "via": parent,
                "cached": self._have_cached_dump(dump)
            } )

    def get_execnet_gateway(self, node, via):
        """Returns a configuration string for execnet's makegatway() function
        for dumping the given node."""
        data = {
            "ssh"   :"root@{}".format(node),
            "id"    : "{}".format(node),
            "python":"python{}".format(2)
        }

        if via:
            data["via"] = via

        parts = ["{}={}".format(key, value) for key, value in data.items()]

        return "//".join(parts)

    def _receive_data(self):

        group = execnet.Group()
        data = {}

        for config in self.m_nodes:
            if config['cached']:
                continue
            node = config['node']
            print("Receiving data from {}".format(node))
            gateway = self.get_execnet_gateway(node, config['via'])
            group.makegateway(gateway)

            config['data'] = group[node].remote_exec(slave).receive()

def main():

    import functools

    def file_path(s, check = os.path.isfile):
        if not os.path.exists(s):
            raise argparse.ArgumentTypeError("The given path does not exist")
        elif not check(s):
            raise argparse.ArgumentTypeError("The given path is not a {}".format(
                "file" if check == os.path.isfile else "directory"
            ))

        return s

    description = "Dump one file per node described in the network configuration"
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)

    description = "The input JSON file your network is described with. Pass 'local' to perform a scan of the local machine"
    parser.add_argument("-i", "--input", type=file_path, help=description)

    description = "The output path you want your data files to be dumped to."
    parser.add_argument("-o", "--output", required=True, type=functools.partial(file_path, check = os.path.isdir), help=description)

    description = "Force overwriting files, even if cached files are already present."
    parser.add_argument("--nocache", action="store_true", help=description)
    description = "Perform a collection on the local machine, conflicts with -i"
    parser.add_argument("-l", "--local", action="store_true", help=description)

    args = parser.parse_args()

    if args.input and args.local:
        raise Exception("Conflicting arguments -i and -l encountered")
    elif not args.input and not args.local:
        raise Exception("Please specify either -i or -l")

    dumper = Dumper()
    dumper.set_output_dir(args.output)
    dumper.set_use_cache(not args.nocache)
    if args.local:
        dumper.collect_local(load_cached = False)
    else:
        dumper.load_network_config(args.input)
        dumper.collect(load_cached = False)
    dumper.save()
    dumper.print_cached_dumps()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(termcolor.colored("Error:", "red"), e)
        raise

