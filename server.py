#!/usr/bin/env python2
import execnet
import self_scan

gw = execnet.makegateway("ssh=root@crowbar.c9.cloud.suse.de")
ch = gw.remote_exec(self_scan)
data = ch.receive()

for d in data:
    print(d)
