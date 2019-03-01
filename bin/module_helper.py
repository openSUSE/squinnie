#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Hamster - scan a system's security related information
# helper module to execute Hamster programs without having to
# fully install the accompanying python modules

# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author: Sebastian Kaim
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
import os
import sys
import pkgutil


def tryFindModule(module):
    """
    Adds .. to the current module path, tries to import $module and
    exits if it is not found.
    """
    # get the full path of the parent directory and append the name
    parent_dir = os.path.realpath(os.path.dirname(os.path.dirname(__file__)))
    sys.path.append(parent_dir)

    # check if the module can be loaded now
    if pkgutil.find_loader(module) is None:
        print("The module %s could not be found in '%s'!" % (module, parent_dir))
        sys.exit(4)


tryFindModule("hamster")
