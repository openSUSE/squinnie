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
import argparse
import sys
import os

# local modules
import helper
pickle = helper.importPickle()

try:
    import termcolor
except ImportError:
    helper.missingModule("termcolor")

class Enricher(object):
    """This class cares for transforming "enriching" the raw data as it is
    collected on a remote or local node into a form that is more suitable for
    our processing."""

    def __init__(self, node_data = None):
        """``node_data`` may contain an already loaded node data
        dictionary."""

        self.m_node_data = node_data

    def _assertData(self):
        if not self.m_node_data:
            raise Exception("No data to save")

    def getDict(self):

        self._assertData()
        return self.m_node_data.itervalues().next()

    def load_data(self, file_name):
        """Load data from the given node data dump file and store it in the
        object."""

        self.m_node_data = helper.readPickle(path = file_name)
        assert len(self.m_node_data.keys()) == 1

    def save_data(self, file_name):
        self._assertData()

        helper.writePickle(self.m_node_data, path = file_name)

    def is_enriched(self):
        """Returns whether the currently loaded node data already has been
        enriched by this class."""
        self._assertData()

        enriched_keys = ["children","uid_name","gid_name"]

        node_dict = self.getDict()

        for key in enriched_keys:
            if key not in node_dict.keys():
                return False

        return True

    def enrich(self):
        """Performs the node data enrichment, if it is not already
        enriched."""

        self._assertData()

        if self.is_enriched():
            return False

        # this is currently the only enrichment performed: recording the
        # parent processes of each process in the dictionary
        self._recordParentChildRelation()

        return True

    def _recordParentChildRelation(self):

        node_dict = self.getDict()
        pids = node_dict["proc_data"].keys()
        parents = node_dict["parents"]

        children = {}
        for p in pids:
            if p in parents.keys():
                # if this is a parent of some other process (i.e. not a leaf
                # process) then record its children in the children dictionary
                the_parent = parents[p]
                childs = children.setdefault(the_parent, [])
                childs.append(p)

        node_dict["children"] = children

def main():
    description = "Enrich the data dump previously collected from a node."
    parser = argparse.ArgumentParser(prog=sys.argv[0], description=description)

    description = "The collected data dump on disk that will be enriched."
    parser.add_argument("-i", "--input", required=True, type=str, help=description)

    args = parser.parse_args()

    enricher = Enricher()
    enricher.load_data(args.input)
    if not enricher.enrich():
        print("Node data is already enriched. Nothing to do.")
        return
    enricher.save_data(args.input)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        if isinstance(e, EOFError):
            # on python2 no sensible error string is contained in EOFError
            e = "Premature end of file"
        print( termcolor.colored("Failed to process node data:", "red"), str(e) )
        sys.exit(1)

