#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
import sys
import os



def perm_readable(file_perm):
    """
    Get access permission as integer
    Output boolean whether access permissions grant read access
    """

    return (file_perm & 4) != 0



def can_access_file(user_identity, file_identity, file_perm):
    """
    arguments may look like this:
    user_identity: {"Uid": 638, "gid_set": [123, 456]}
    file_identity: {"Uid": 378, "Gid": 547}
    file_perm    : {"Uid": 123, "Gid": 456, "other": 789}
    """

    # uid
    if file_identity["Uid"] == user_identity["Uid"]:
        if perm_readable(file_perm["Uid"]):
            return True

    # gid
    elif file_identity["Gid"] in user_identity["Gid_set"]:
        if perm_readable(file_perm["Gid"]):
            return True

    # other
    else:
        if perm_readable(file_perm["other"]):
            return True

    return False



def get_fd_metadata_str(metadata_int):
    result = []

    # Only available since Python 3.3
    if sys.version_info < (3, 3):
        os.O_CLOEXEC = 524288

    if metadata_int & os.O_WRONLY:
        result.append("O_WRONLY")
    if metadata_int & os.O_RDWR:
        result.append("O_RDWR")
    if metadata_int & os.O_CLOEXEC:
        result.append("O_CLOEXEC")

    return result
