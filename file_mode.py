import sys
import os
from stat import *

# Copied from Python 3.3
# Python 2.7 really does not have this included
_filemode_table = (
    ((S_IFLNK,         "l"),
     (S_IFREG,         "-"),
     (S_IFBLK,         "b"),
     (S_IFDIR,         "d"),
     (S_IFCHR,         "c"),
     (S_IFIFO,         "p")),

    ((S_IRUSR,         "r"),),
    ((S_IWUSR,         "w"),),
    ((S_IXUSR|S_ISUID, "s"),
     (S_ISUID,         "S"),
     (S_IXUSR,         "x")),

    ((S_IRGRP,         "r"),),
    ((S_IWGRP,         "w"),),
    ((S_IXGRP|S_ISGID, "s"),
     (S_ISGID,         "S"),
     (S_IXGRP,         "x")),

    ((S_IROTH,         "r"),),
    ((S_IWOTH,         "w"),),
    ((S_IXOTH|S_ISVTX, "t"),
     (S_ISVTX,         "T"),
     (S_IXOTH,         "x"))
)

# Copied from Python 3.3
def filemode(mode):
    """Convert a file's mode to a string of the form '-rwxrwxrwx'."""
    if mode == None: # Broken symlinks have no permissions
        return "!PERMERROR"

    perm = []
    for table in _filemode_table:
        for bit, char in table:
            if mode & bit == bit:
                perm.append(char)
                break
        else:
            perm.append("-")
    return "".join(perm)


def get_file_type(mode):
    if mode == None:
        return "!MODEERROR!"

    filetypes = []
    # directory
    if S_ISDIR(mode):
        filetypes.append("directory")

    # regular file
    if S_ISREG(mode):
        filetypes.append("regular file")

    # symbolic link
    if S_ISLNK(mode):
        filetypes.append("symbolic link")

    # FIFO (named pipe)
    if S_ISFIFO(mode):
        filetypes.append("FIFO (named pipe)")

    # socket
    if S_ISSOCK(mode):
        filetypes.append("socket")

    # character special device file
    if S_ISCHR(mode):
        filetypes.append("character special device file")

    # block special device file
    if S_ISBLK(mode):
        filetypes.append("block special device file")

    return "".join(filetypes)



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
