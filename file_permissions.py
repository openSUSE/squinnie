#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
import sys

def perm_readable(file_perm):
    """
    Get access permission as integer
    Output boolean whether access permissions grant read access
    """

    return (file_perm & 4) != 0



def can_access_file(user_identity, file_identity, file_perm):
    """
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
