import os

ROOT = os.path.dirname(os.path.dirname(__file__))

def getDataFile(basename):
    """Returns the full path to a data file like *.json files independently of
    the program being run from a git checkout, from a --user installation or a
    global installation."""

    return os.path.join(ROOT, "etc", basename)
