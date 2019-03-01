#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Hamster - scan a system's security related information
# this program prints the contents of a dumpfile

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

import pprint
import sys
import module_helper
from hamster import helper

if len(sys.argv) < 2:
    print('Usage: %s <dump.p.gz> [depth]' % sys.argv[0])
    sys.exit(1)

data = helper.readPickle(sys.argv[1])

depth=2
if len(sys.argv) >= 3:
    depth = int(sys.argv[2])

pprint.pprint(data, indent=2, depth=depth)

