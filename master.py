#!/usr/bin/env python3
"""
This script is intended to be run on the master.
Tested only on Python 3, since the execnet_importhook module only
supports Python 3.
"""

import execnet
import execnet_importhook # https://github.com/kelleyk/execnet-importhook
import slave as collector

entry_node = "crowbar.c9.cloud.suse.de"
group = execnet.Group()
master = group.makegateway("python=python3//id=master//ssh=root@"+entry_node)

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

    slave  = group.makegateway("python=python3//via=master//ssh=root@"+node)
    execnet_importhook.install_import_hook(slave)
    python_cmd = "import os; channel.send(os.uname()[1])"
    str_slave = slave.remote_exec(python_cmd).receive()
    print("Hostname: "+str_slave)

    collected_data = slave.remote_exec(collector).receive()
    # print("There are in total %d processes running on this system." % len(collected_data))
    print(collected_data)

    print("")
