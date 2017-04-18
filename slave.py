#!/usr/bin/env python3
"""
This script is intended to be run on the slave, even though also be run
on any host as a standalone script.
Tested only on Python 3, since the execnet_importhook module only
supports Python 3.
"""

# Packages that Python ships with
import os
import sys
import re

# The following packages have to be installed on the master using the package
# manager (e.g. zypper) or pip.
import proc

if __name__ == '__channelexec__':
    channel.send((sys.platform, tuple(sys.version_info), os.getpid()))















"""
result = []

# traverse root directory, and list directories as dirs and files as files
for entry in os.listdir("/proc"):

    fp = os.path.join( "/proc", entry )

    if not os.path.isdir(fp):
        continue

    try:
        pid = int(entry)
    except ValueError:
        continue

    result.append(pid) # TODO: Save more than just the PID

        # TODO: Export other useful information about this node
"""
