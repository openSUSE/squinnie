# -*- coding: utf-8 -*-
# vim: ts=4 et sw=4 sts=4 :

# Squinnie - scan a system's security related information
# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author:     Matthias Gerstner
#
# see LICENSE file for detailed licensing information


class ScannerError(Exception):
    """Specialized exception type for usage and logical errors detected
    during execution of the scanner.
    """

    def __init__(self, *args, **kwargs):

        Exception.__init__(self, *args, **kwargs)

