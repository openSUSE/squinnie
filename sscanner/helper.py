# -*- coding: utf-8 -*-
# vim: ts=4 et sw=4 sts=4 :

# security scanner - scan a system's security related information
# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author:     Matthias Gerstner
#
# see LICENSE file for detailed licensing information

from __future__ import print_function
import sys

# a place for assorted code shared between functions


def isPython2():
    return sys.version_info.major == 2


def isPython3():
    return not isPython2()


def eprint(*args, **kwargs):
    """Wrapper around print() function that writes to stderr by default."""
    print(*args, file=sys.stderr, **kwargs)


def missingModule(which = None, ex = None):
    """Prints an error message about a missing module and exits."""

    if which == None:
        which = ex.message.split()[-1]

    eprint("The module {} could not be found. Please use your system's package manager or pip to install it.".format(which))
    sys.exit(1)


def importPickle():
    """
    Import the pickle module in a python agnostic way.

    The regular pickle module is the same in python2 and python3, but the
    cPickle module is named differently. cPickle is implemented in C and
    supposedly way faster. Since we're processing large amounts of data in
    s²canner it seems sensible to use it.

    The interface of all modules should be the same.
    """
    if isPython2():
        import cPickle as pickle
    else:
        import _pickle as pickle
        import functools
        # replace the load function by a utf-8 aware function.
        # python2 does not support this parameter.
        pickle.load = functools.partial(
            pickle.load, encoding = 'utf-8'
        )

        if not hasattr(pickle, "HIGHEST_PROTOCOL"):
            # this constant is missing in _pickle in python3
            pickle.HIGHEST_PROTOCOL = 4

    return pickle


def writePickle(item, path = None, fileobj = None):
    """
    Write the given python object ``item`` to the given path of file object.

    Provide either ``path`` or ``fileobj``, not both.

    :param str path: File system path where to write the pickle to. Will be
    overwritten if it already exists.
    :param file fileobj: A file like object that is already open where the
    pickle data will be written to. Must be opened in 'wb' mode.
    """
    import gzip
    pickle = importPickle()

    if path and fileobj:
        raise Exception("path and fileobj passed, don't know what to do")
    elif path:
        fileobj = open(path, 'wb')

    if not fileobj:
        raise Exception("no file/path passed")

    try:
        with gzip.GzipFile(fileobj = fileobj, mode = 'wb') as zifi:
            pickle.dump(item, zifi, protocol = pickle.HIGHEST_PROTOCOL)
    finally:
        if path:
            fileobj.close()


def readPickle(path = None, fileobj = None):
    """
    Return data from a pickle file.

    Provide either ``path`` or ``fileobj``, not both.

    :param str path: File system path from where to read the pickle from.
    :param file fileobj: A file like object that is already open where the
    pickle data will be read from. Must be opened in 'rb' mode.
    """
    import gzip
    pickle = importPickle()

    if path and fileobj:
        raise Exception("path and fileobj passed, don't know what to do")
    elif path:
        fileobj = open(path, 'rb')

    if not fileobj:
        raise Exception("no file/path passed")

    try:
        with gzip.GzipFile(fileobj = fileobj, mode = 'rb') as zifi:

            import cStringIO
            data = cStringIO.StringIO(zifi.read())

            ret = pickle.load(data)
    finally:
        if path:
            fileobj.close()

    return ret


def executeMain(call):
    """Runs the given function call wrapped in try/except clauses that provide
    sensible error handling and output."""

    try:
        import termcolor
        from . import errors
    except ImportError as e:
        missingModule(ex = e)

    try:
        call()
        return
    except errors.ScannerError as e:
        print(termcolor.colored("Error:", color = "red"), e)
    except EnvironmentError as e:
        print(termcolor.colored("Failed:", color = "red"), e)
    except Exception as e:
        print(termcolor.colored("Unexpected error:", color = "red"))
        raise

    sys.exit(1)

