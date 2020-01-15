#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author:     Matthias Gerstner
# see LICENSE file for detailed licensing information

# this file keeps helper types that are used across the modules

class Modes(object):
    """enum-like class for holding the different Squinnie modes we
    support"""

    all_modes = ["local", "ssh", "susecloud", "auto"]

    @classmethod
    def fillModes(cls):
        for mode in cls.all_modes:
            setattr(cls, mode, mode)

    @classmethod
    def checkModeArg(cls, mode):

        if not mode.lower() in cls.all_modes:
            import argparse
            raise argparse.ArgumentTypeError(
                "unsupported mode, choose one of {}".format(
                    ', '.join(cls.all_modes)
                )
            )

        return getattr(cls, mode)

Modes.fillModes()

class ProcColumns(object):
    """enum-like class for holding the different columns in a proc view."""

    # order of these matter, it defines the order of the columns in outputs
    all_columns = [
        "pid", "executable", "parameters", "user", "groups", "open_fds", "umask", "features", "cap_inherit", "cap_perm",
        "cap_eff", "cap_bnd", "cap_ambient", "threads", "rtime", "namespace"
    ]

    @classmethod
    def fillCols(cls):
        labels = {
            "open_fds": "open file descriptors",
            "cap_inherit": "CapInh",
            "cap_perm": "CapPrm",
            "cap_eff": "CapEff",
            "cap_bnd": "CapBnd",
            "cap_ambient": "CapAmb",
            "rtime": 'running time'
        }

        cls.m_labels = dict()
        cls.m_all = list()
        num = 1
        for col in cls.all_columns:
            setattr(cls, col, num)
            label = labels.get(col, col)
            cls.m_labels[num] = label
            cls.m_all.append(num)
            num += 1

        cls.m_max_value = num

    @classmethod
    def checkColArg(cls, col):
        if not col.lower() in cls.all_columns:
            import argparse
            raise argparse.ArgumentTypeError(
                "unsupported column, choose one of {}".format(
                    ', '.join(cls.all_columns)
                )
            )

    @classmethod
    def getLabel(cls, col):
        return cls.m_labels[col]

    @classmethod
    def getAll(cls):
        import copy
        return copy.copy(cls.m_all)

    @classmethod
    def isCap(cls, col):
        return col in (cls.cap_inherit, cls.cap_perm, cls.cap_eff,
                cls.cap_bnd, cls.cap_ambient)

ProcColumns.fillCols()
