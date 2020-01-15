#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Squinnie - scan a system's security related information
# this translator filters, rearranges and parses collected network
# interface data into a displayable form

# Copyright (C) 2018 SUSE LINUX GmbH
#
# Author: Jannik Main
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

import os
import json
import struct
import socket

class NwIfaceTranslator(object):
    """
    This class contains various helper functions to correctly parse the
    Network Interface Information received.
    """

    m_nwifile = "bitflag_data.json"
    m_typefile = "type_data.json"

    def __init__(self, nwi_name=None, type_name=None):
        self.nwi_name = nwi_name if nwi_name else self.m_nwifile
        self.type_name = type_name if type_name else self.m_typefile
        self.nwi_data = self._getFileData(self.m_nwifile)
        self.type_data = self._getFileData(self.m_typefile)

    def _getFileData(self, fileName):
        import squinnie
        filePath = squinnie.getDataFile(fileName)

        try:
            with open(filePath, "r") as f:
                return json.load(f)
        except EnvironmentError as e:
            raise squinnie.errors.ScannerError(
                "Cannot open file {}: {}".format(args.input, str(e))
            )

    def _getNwiFlags(self):
        # initialize empty array for all flags
        result = [None]*len(self.nwi_data)
        for flag_name, index in self.nwi_data.items():
            result[index] = flag_name
        return result

    def parseNwiFlags(self, value):
        """
        This helper transforms network device bit flags to their according
        value. The flags are then filtered.
        :string value: the flags represented as hexadecimal value
        """
        #interesting flags
        valid_flags = [
            'LOOPBACK', 'RUNNING', 'PROMISC', 'SLAVE', 'LOWER_UP', 'UP'
        ]
        # flags extracted from /usr/include/linux/if.h
        types = self._getNwiFlags()
        result = []
        value = int(value, 16)
        for t in range(0, len(types)):
            if 1<<t & value >= 1:
                if types[t] in valid_flags:
                    result.insert(0, types[t])
        return result

    def parseType(self, value):
        for type_str, val in self.type_data.items():
            if val == value:
                return type_str

    def ipv6(self, addr):
        """
        This helper converts a full digit representation of an IPv6
        address to the more readable format.
        :string addr: the full digit IPv6 address
        """
        addr = struct.unpack('<IIII', addr.decode('hex'))
        addr = struct.pack('@IIII', *addr)
        addr = socket.inet_ntop(socket.AF_INET6, addr)
        return addr

    def getExcessLines(self, excess, fields, output):
        """
        This helper adds excess Data and fields, whose content
        should be seperated into multiple lines, to formatted data.
        :dictionary excess: contains field-name as key and excess list
        as value
        :list fields: the list indices inside data
        :list output: the existing formatted lines for terminal output
        """
        while len(excess) > 0:
            result = [''] * len(fields)
            excess_work = excess.copy()
            for key in excess_work:
                result[fields.index(key)] = excess[key].pop()
                if not excess[key]:
                    del excess[key]
            output.append(result)

    def getFormattedData(self, data, identifier):
        """
        This helper takes the collected information and selects the
        interesting data.
        :dictionary data: the Network Interface information collected
        from Squinnie
        :list identifier: the interesting keys inside each interface
        sub-dictionary
        """
        output = []
        for iface in data:
            excess = {}
            iface_data = []
            for col in identifier:
                result = ""
                if col in data[iface]:
                    if col == "flags":
                        for flags in self.parseNwiFlags(data[iface][col][0]):
                            result = " ".join((result, flags))
                        result = result[1:]
                    elif col == "type":
                        result = self.parseType(int(data[iface][col][0]))
                    elif col == "uevent":
                        for uev in data[iface][col]:
                            field, val = uev.split('=')
                            if(field == "DEVTYPE"):
                                result = val
                    elif col == "ipv6":
                        val = [''] * (len(data[iface][col])/2)
                        for index in range(0, len(val)):
                            val[index] = "/".join(
                                    (self.ipv6(data[iface][col][index*2]
                                    ),
                                    str(int(data[iface][col][index*2+1], 16))
                                    ))
                        result = val[0]
                        if len(val) > 1:
                            excess[col] = val[1:]
                    elif col == "ipv4" or col == "attached":
                        val = [''] * len(data[iface][col])
                        for index in range(0, len(val)):
                            val[index] = data[iface][col][index]
                        result = val[0]
                        if len(val) > 1:
                            excess[col] = val[1:]
                    else:
                        result = data[iface][col][0]
                iface_data.append(result)
            if data[iface]["carrier"][0] == '1':
                iface_data[identifier.index("flags")] = " ".join((
                        iface_data[identifier.index("flags")
                        ], self.parseNwiFlags('0x10000')[0]
                ))
            output.append(iface_data)
            if excess:
                self.getExcessLines(excess, identifier, output)
        return output
