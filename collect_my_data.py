#!/usr/bin/env python2
"""
This is the scanner file running on the client. We have to use Python 2 for
now, since Python 3 is not available by default in the latest SLES.
"""
import os
import re

if __name__ == '__channelexec__':
    result = []

    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk("/proc"):
        regex = "^\/proc\/\d*$"
        if re.search(regex, root):
            result.append(root) # TODO: Save more than just the PID

        # TODO: Export other useful information about this node

    channel.send(result)
