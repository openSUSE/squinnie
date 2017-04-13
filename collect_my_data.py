#!/usr/bin/env python2
"""
This is the scanner file running on the client. We have to use Python 2 for
now, since Python 3 is not available by default in the latest SLES.
"""
from __future__ import print_function
import os
import re

if __name__ == '__channelexec__':
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

    channel.send(result)

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
