#!/usr/bin/env python2
"""
This script is intended to be run on the master.
"""

# Standard library modules.
from __future__ import print_function
from __future__ import with_statement
import sys
from collections import OrderedDict
import json

# PyPy modules
import execnet

# External dependencies.
import slave as collector

entry_node = "crowbar.c9.cloud.suse.de"
group = execnet.Group()
master = group.makegateway("id=master//python=python%d//ssh=root@%s" % (sys.version_info.major, entry_node))

cmd = "crowbar machines list"
exec_cmd = "import os; channel.send(os.popen('%s').read())" % (cmd)
str_crowbar = master.remote_exec(exec_cmd).receive()

# One newline too much leads to one empty string
all_nodes = str_crowbar.split("\n")
all_nodes = list(filter(None, all_nodes))

print("Found the following nodes:")
for node in all_nodes:
    print(node)
print("")

print("Running the module on all nodes:")
for node in all_nodes:
    print("Node:     "+node)

    slave  = group.makegateway("via=master//python=python%d//ssh=root@%s" % (sys.version_info.major, node))
    python_cmd = "import os; channel.send(os.uname()[1])"
    str_slave = slave.remote_exec(python_cmd).receive()
    print("Hostname: "+str_slave)

    collected_data_str = slave.remote_exec(collector).receive()
    collected_data = json.loads(collected_data_str, object_pairs_hook=OrderedDict)
    print("There are in total %d processes running on this system." % len(collected_data["status"].keys()))

    print("Here are the first 20 lines of the JSON data:")
    for l in collected_data_str.split("\n")[:20]:
        print(l)
    print("...")
    print("")

    print("")
