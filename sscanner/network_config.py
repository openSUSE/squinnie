#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author:     Matthias Gerstner
# see LICENSE file for detailed licensing information

from collections import OrderedDict
import json

class NetworkConfig(object):
    """This class is responsible for saving and loading network information
    to/from disk.
    
    network information currently is a dictionary of the form {
        "entry_node": ["back_node1", "back_node2", ...]
    }

    which is stored as JSON on disk.
    """

    def __init__(self):

        self.m_network = {}

    def setNetwork(self, nd):
        self.m_network = nd

    def getNetwork(self):
        return self.m_network

    def save(self, path):
            
        try:
            with open(path, "w") as fi:
                json.dump(path, fi, indent=4, sort_keys=True)
        except Exception as e:
            raise Exception("Failed to write JSON network configuration to {}: {}".format(path, str(e)))

    def load(self, path):
        
        try:
            with open(path, "r") as fi:
                self.m_network = json.load(fi, object_pairs_hook=OrderedDict)
        except Exception as e:
            raise Exception("Failed to read JSON network configuration from {}: {}".format(path, str(e)))

        assert len(self.m_network.keys()) == 1
        return self.m_network

