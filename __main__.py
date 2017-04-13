#!/usr/bin/env python2
"""
Using Python 2 for now, since execnet seems to have problems with latest SLES.
"""
import execnet
import collect_my_data

entry_node = "crowbar.c9.cloud.suse.de"
group = execnet.Group()
master = group.makegateway("id=master//ssh=root@"+entry_node)

cmd = "crowbar machines list"
exec_cmd = "import os; channel.send(os.popen('"+cmd+"').read())"
str_crowbar = master.remote_exec(exec_cmd).receive()
all_nodes = str_crowbar.split("\n")
all_nodes = filter(None, all_nodes)

print("Found the following nodes:")
for node in all_nodes:
    print(node)
print("")

print("Running the module on all nodes:")
for node in all_nodes:
    print("Node:     "+node)
    slave  = group.makegateway("via=master//ssh=root@"+node)
    str_slave = slave.remote_exec("import os; channel.send(os.uname()[1])").receive()
    print("Hostname: "+str_slave)

    collected_data = slave.remote_exec(collect_my_data).receive()
    print("There are in total %d processes running on this system." % len(collected_data))

    print("")
