# -*- coding: utf-8 -*-
# vim: ts=4 et sw=4 sts=4 :

# security scanner - scan a system's security related information
# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author:     Matthias Gerstner
#
# see LICENSE file for detailed licensing information

from __future__ import print_function
import os, sys

# a place for assorted code shared between functions

def isPython2():
    return sys.version_info.major == 2

def isPython3():
    return not isPython2()

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

    return pickle
