# -*- coding: utf-8 -*-
# vim: ts=4 et sw=4 sts=4 :

# Squinnie - scan a system's security related information
# contains different supporting methods mainly around pickle

# Copyright (C) 2017 SUSE LINUX GmbH
#
# Authors: Matthias Gerstner, Sebastian Kaim
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301 USA.

from __future__ import print_function
import sys
import re
import logging

# a place for assorted code shared between functions


def isPython2():
    return sys.version_info.major == 2


def isPython3():
    return not isPython2()


def eprint(*args, **kwargs):
    """Wrapper around print() function that writes to stderr by default."""
    print(*args, file=sys.stderr, **kwargs)


def missingModule(which=None, ex=None):
    """
    Prints an error message about a missing module and exits.
    :param string which: name of the missing module
    :param exception ex: exception thrown
    """
    if which is None:
        which = ex.message.split()[-1]

    logging.critical("The module {} could not be found. Please use your system's package manager or pip to install it.".
                     format(which))
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


def writePickle(item, path=None, fileobj=None):
    """
    Write the given python object ``item`` to the given path of file object.

    Provide either ``path`` or ``fileobj``, not both.

    :param item: The data to write.
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
        with gzip.GzipFile(fileobj=fileobj, mode='wb') as zifi:
            pickle.dump(item, zifi, protocol=pickle.HIGHEST_PROTOCOL)
    finally:
        if path:
            fileobj.close()


def readPickle(path=None, fileobj=None):
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
        with gzip.GzipFile(fileobj=fileobj, mode='rb') as zifi:

            import cStringIO
            data = cStringIO.StringIO(zifi.read())

            ret = pickle.load(data)
    finally:
        if path:
            fileobj.close()

    return ret


def executeMain(call):
    """Runs the given function call wrapped in try/except clauses that provide
    sensible error handling and output.
    """
    try:
        import termcolor
        from . import errors
    except ImportError as e:
        missingModule(ex=e)

    try:
        call()
        return
    except errors.ScannerError as e:
        print(termcolor.colored(str(e), color = 'red'))
    except EnvironmentError as e:
        logging.critical(e)
    except Exception as e:
        logging.critical(e)
        raise

    sys.exit(1)


def makeValidDirname(s):
    """
    This function makes a valid file- or directory name from a string by removing leading and trailing spaces,
    converting other spaces to underscores and removing anything that is not an alphanumeric, dash or underscore.
    """
    return re.sub(r'(?u)[^-\w.]', '', s.strip().replace(' ', '_'))


def getLogger():
    """Returns the logger for the project."""
    logging.getLogger("squinnie")

def changeTimeFormat(runtime):
    """Improves the readability of process-runtime.

    Only useful, if runtime is greater than 60s.
    :float runtime: the runtime in seconds
    :string return: runtime divided in hours, minutes and seconds
    """
    result = ""
    runtime_int = int(runtime)
    runtime_orig = runtime_int
    #extract hours
    if runtime_int > 3600:
        result += str(runtime_int / 3600) + 'h:'
        runtime_int = runtime_int % 3600
    #extract minutes
    result += str('{:02}'.format(runtime_int / 60)) + 'm:'
    runtime_int = runtime_int % 60
    #pre-decimal-point value must eqal runtime_int
    runtime -= float(runtime_orig - runtime_int)
    return result + str("{:05.2f}".format(runtime)) + 's'
