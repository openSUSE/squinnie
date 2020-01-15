#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# Squinnie - scan a system's security related information
# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author: Benjamin Deuter, Sebastian Kaim, Jannik Main
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

# Standard library modules.
from __future__ import with_statement
import sys
import os
import stat
import subprocess
import logging
import textwrap
from collections import OrderedDict
# Local modules.
import squinnie.cap_translator as cap_translator
import squinnie.helper as helper
import squinnie.file_mode as file_mode
import squinnie.errors
import squinnie.nwiface_translator as nwiface_translator
from squinnie.types import ProcColumns
from squinnie.daw.fs import FsQuery
from squinnie.dio import DumpIO
from squinnie.daw import factory
from squinnie.ldump import LocalFactory

pickle = helper.importPickle()

# foreign modules
try:
    import terminaltables
    import termcolor
except ImportError as e:
    helper.missingModule(ex=e)


class Viewer(object):
    """This class implements the various view operations on node data."""

    def __init__(self, daw_factory, label):

        self.m_gid_filter = -1
        self.m_uid_filter = -1
        self.m_fsquery = FsQuery()
        self.m_verbose = False
        self.m_have_tty = os.isatty(sys.stdout.fileno())
        self.m_show_fds = False
        self.m_show_params = False
        self.m_pid_filter = []
        self.m_show_filter_parents = False
        self.m_show_filter_children = False
        self.m_show_threads = False
        self.m_show_kthreads = False
        self.m_indentation_width = 4
        self.m_node_label = label
        self.m_show_numeric = False
        self.m_used_namespaces = []
        self.m_ns_pid = None
        self.m_account_helper = None

        self.m_cap_translator = cap_translator.CapTranslator(
                self._getJsonFile("cap_data")
        )
        self.m_nwiface_translator = nwiface_translator.NwIfaceTranslator(
                nwi_name=self._getJsonFile("bitflag_data"),
                type_name=self._getJsonFile("type_data")
        )

        self.m_daw_factory = daw_factory
        self.m_proc_wrapper = self.m_daw_factory.getProcWrapper()

        self.m_excluded = []
        self.m_included = []

    def _getJsonFile(self, filename):
        return squinnie.getDataFile("{}.json".format(filename))

    def getAccountHelper(self):
        if not self.m_account_helper:
            ns_helper = self.m_daw_factory.getNamespacesWrapper()
            uid_gid = ns_helper.getNamespaceUidGid()
            self.m_account_helper = self.m_daw_factory.getAccountWrapper(uid_gid)
        return self.m_account_helper

    def activateSettings(self, args):
        """Activates the settings found in the given argparse.Namespace
        object."""
        self.setVerbose(args.verbose)
        self.setShowFds(args.fd)
        self.setShowParams(args.params)
        self.setShowKthreads(args.kthreads)
        self.setShowThreads(args.threads)
        self.setShowFilterChildren(args.children)
        self.setShowFilterParents(args.parent)
        self.parseOwnerFilters(args)
        self.createFsQuery(args)
        self.setExcludeInclude(args)

    def parseOwnerFilters(self, args):
        account_helper = self.getAccountHelper()

        if args.user:
            self.m_uid_filter = account_helper.getUidForName(args.user)
        if args.group:
            self.m_gid_filter = account_helper.getGidForName(args.group)

        if args.uid > 0:
            self.m_uid_filter = args.uid
        if args.gid > 0:
            self.m_gid_filter = args.gid

    def performAction(self, args):
        """Performs the action specified in the given argparse.Namespace
        object."""
        if args.pid:
            self.addPidFilter(args.pid)

        if args.onlyfd:
            # file descriptor view
            self.printFileDescriptors()
        elif args.filesystem:
            # file-system view
            self.printFilesystemTable()
        elif args.svipc:
            # systemv ipc view
            self.printSystemVIPC()
        elif args.network_interfaces:
            # network interface information view
            self.printNetworkInterfaces()
        elif args.namespaces:
            # namespace information view
            self.printNamespaces()
        else:
            # process tree view
            self.printProcessTree()

    @classmethod
    def addParserArguments(cls, parser):
        """Adds the viewer specific command line arguments to the given
        argparse.ArgumentParser object."""
        # this is for reuse in the main Squinnie script.

        description = "A comma-separated list of columns to include in the output."
        parser.add_argument("--cols", type=str, help=description)

        description = "A comma-separated list of columns to exclude in the output."
        parser.add_argument("-x", "--exclude", type=str, help=description)

        description = "Show parameters from the process's cmdline entry."
        parser.add_argument("--params", action="store_true", help=description)

        description = "Include threads. Kernel threads are excluded by default."
        parser.add_argument("--threads", action="store_true", help=description)

        description = "Include kernel threads. Kernel threads are excluded by default."
        parser.add_argument("-k", "--kthreads", action="store_true", help=description)

        description = "Only show data that belongs to the provided pid."
        parser.add_argument("-p", "--pid", type=int, help=description)

        description = "Also print all the children of the process provided by -p/--pid."
        parser.add_argument("--children", action="store_true", help=description)

        description = "Print the parent of the process provided by -p/--pid."
        parser.add_argument("--parent", action="store_true", help=description)

        description = "Show all open file descriptors for every process."
        parser.add_argument("--fd", action="store_true", help=description)

        description = "Show only the open file descriptors in a dedicated view and nothing else."
        parser.add_argument("--onlyfd", action="store_true", help=description)

        description = "Show the system V IPC data."
        parser.add_argument("--svipc", action="store_true", help=description)

        description = "View all files on the file system, including their permissions."
        parser.add_argument("--filesystem", action="store_true", help=description)

        description = "Only show files with special bits set (sticky, suid or sgid) or missing."
        parser.add_argument("--special-bits", "-s", action="store_true", help=description)

        description = "Only show files with capabilities."
        parser.add_argument("--capabilities", "-c", action="store_true", help=description)

        # helper datatype defintion
        def octint(inp):
            return int(inp, 8)

        description = "Only show files which have at least one of the bits set from given mode."
        parser.add_argument("--has-mode", type=octint, default=-1, help=description)

        description = "Only show files which have all of the bits set from given filemode."
        parser.add_argument("--filemode-min", type=octint, default=-1, help=description)

        description = "Only show files which have none the bits set from given filemode."
        parser.add_argument("--filemode-max", type=octint, default=-1, help=description)

        description = "Only show files which match the given file mode."
        parser.add_argument("--filemode", type=octint, default=-1, help=description)

        description = "Add an extra output column with a verbose representation of the suid bit (S_ISUID), the gid " \
                      "bit (S_ISGID) and the sticky bit (S_ISVTX). This is to allow easier combination with grep."
        parser.add_argument("--verbose-special-bits", action="store_true", help=description)

        description = "Show only files of a specific type."
        parser.add_argument("--type", "-t", type=str, default=None, help=description,
                            choices=file_mode.getPossibleFileChars())
        description = "Show network interface information"
        parser.add_argument("--network-interfaces", action="store_true", help=description)
        desc = "Show information about available namespaces"
        parser.add_argument("--namespaces", action="store_true", help=desc)

        description = "Show values in numeric format"
        parser.add_argument("--numeric", action="store_true", help=description)

    def addPidFilter(self, pid):
        """Don't show all PIDs but just the given PID in the table.
        Accumulates."""
        self.m_pid_filter.append(pid)

    def setVerbose(self, verbose):
        self.m_verbose = verbose

    def setShowFds(self, show):
        """Also show per process file descriptor info."""
        self.m_show_fds = show

    def setShowParams(self, show):
        """Also show process parameters in an extra column."""
        self.m_show_params = show

    def setShowFilterParents(self, show):
        """If a PID filter is in effect, also show the parents of selected
        PIDs."""
        self.m_show_filter_parents = show

    def setShowFilterChildren(self, show):
        """If a PID filter is in effect, also show the children of selected
        PIDs."""
        self.m_show_filter_children = show

    def setShowKthreads(self, show):
        """Also include kernel thread PIDs in the table."""
        self.m_show_kthreads = show

    def collectUsedNamespaces(self):
        """
        Reorders collected namespace data.
        :list self.m_used_namespaces: contains inode/data tuples.
        """
        namespaces = self.m_daw_factory.getNamespacesWrapper()
        data = namespaces.getAllNamespaceData()
        self.m_used_namespaces = sorted(data.items(), key=lambda k: k[1]['nbr'])
        self.m_deep_namespace_data = namespaces.getAllDeepNsData()

    def printFileDescriptors(self):
        """Prints all file descriptors of all processes found in the current
        data set."""

        proc_wrapper = self.m_proc_wrapper
        descriptorless_pids = []

        for pid, info in OrderedDict(proc_wrapper.getProcData()).items():
            open_file_count = len(info["open_files"])

            # skip filtered PIDs
            if self.m_uid_filter and self.m_uid_filter not in info['Uid']:
                continue
            if self.m_gid_filter and self.m_gid_filter not in info['Gid']:
                continue

            # Hide the process if it has no open files
            # But always show all processes on -v
            if open_file_count > 0:
                # list_str = self.getListOfOpenFileDescriptors(info)
                wrapper = proc_wrapper.getFileDescriptorsForPid(pid)

                print("{} (pid: {})".format(info["executable"], pid))
                print("----")
                print(wrapper.toString())
                print("")
            else:
                descriptorless_pids.append(pid)

        if self.m_verbose:  # only tell there are no processes w/o file descriptors if we're verbose
            if len(descriptorless_pids) > 0:
                print("PIDs without open file descriptors [{}]: {}"
                      .format(len(descriptorless_pids), ", ".join([str(i) for i in sorted(descriptorless_pids)])))
            else:
                print('There were no PIDs without open file descriptors.')

    @staticmethod
    def buildWidthColumnDict(table):
        """Builds a dictionary containing the maximum width for each column in
        the given table list."""
        width_column_dict = {}
        for i in range(len(table[0])):
            width_column_dict[i] = max(len(row[i]) for row in table)

        return width_column_dict

    @staticmethod
    def printTableWidthColumnDict(table, width_column_dict, max_width):
        for row in table:
            to_print = " ".join(row[i].ljust(width_column_dict[i]) for i in range(len(table[0])))
            if max_width:
                print(to_print[:max_width])
            else:
                print(to_print)

    def getFilesystemTable(self):
        """
        Recursively constructs and returns list of strings that describes the
        complete file system structure rooted at cur_path/cur_node.
        """

        fshandler = self.m_daw_factory.getFsWrapper()
        iterator = fshandler.queryFilesystem(self.m_fsquery)

        account_wrapper = self.getAccountHelper()

        ret = []

        while iterator.next():
            user = account_wrapper.getNameForUid(iterator.uid, default="(unknown)")
            group = account_wrapper.getNameForGid(iterator.gid, default="(unknown)")

            caps = self.m_cap_translator.getCapStrings(iterator.caps)
            cap_str = "|".join(caps)

            ret.append(
                [
                    iterator.getPermissionString(),
                    iterator.getTypeLabel(),
                    user,
                    group,
                    cap_str,
                    iterator.getFullPath()
                ]
            )

        return ret

    def getColumnValue(self, column, pid):
        """
        Get the string value for the given table ``column`` of the given
        process with ``pid``.
        """

        proc_wrapper = self.m_proc_wrapper

        pid_data = proc_wrapper.getProcessInfo(pid)

        if "Uid" not in pid_data.keys():
            return ""

        return self.formatColumnValue(column, pid, pid_data)

    def formatColumnValue(self, column, pid, pid_data, cap_color='red'):
        account_wrapper = self.getAccountHelper()

        column_label = ProcColumns.getLabel(column)

        # check whether a process runs with surprising saved/effective uid/gid
        all_uids_equal = len(set(pid_data["Uid"])) == 1
        all_gids_equal = len(set(pid_data["Gid"])) == 1

        if column == ProcColumns.user:
            user_set = set()

            for userid in set(pid_data["Uid"]):
                if self.m_verbose:
                    user_label = "{}({})".format(account_wrapper.getNameForUid(userid), userid)
                else:
                    user_label = account_wrapper.getNameForUid(userid)
                user_set.add(user_label)

            result = "|".join(str(x) for x in user_set)
            if not all_uids_equal:
                result = self.getColored(result)

        elif column == ProcColumns.groups:
            # merge the main gid and the auxiliary group ids
            groups_set = set(pid_data["Gid"]) | set(pid_data["Groups"])
            groups = set()

            for groupid in groups_set:
                if self.m_verbose:
                    group_label = "{}({})".format(account_wrapper.getNameForGid(groupid), groupid)
                else:
                    group_label = account_wrapper.getNameForGid(groupid)
                groups.add(group_label)

            groups = list(groups)
            # wrap around long group lines by not having more than four groups
            # on a line
            result = ""
            for i in range(len(groups)):
                if i != 0:
                    result += "|"
                    result += "\n" if (i % 4) == 0 else ""
                result += str(groups[i])

            result = result.rstrip("|")

            if not all_gids_equal:
                result = self.getColored(result)

        elif column == ProcColumns.threads:
            result = str(len(pid_data['threads']))

        elif column == ProcColumns.rtime:
            sdata_wrapper = self.m_daw_factory.getSystemDataWrapper()
            runtime = sdata_wrapper.getProcessUptime(pid_data['starttime'])
            #human readable time format
            if (not self.m_show_numeric and runtime > float(60)):
                return helper.changeTimeFormat(runtime)
            #runtime rounded to two numbers after decimal point
            return str("{0:.2f}".format(runtime)) + 's'

        elif column == ProcColumns.features:
            features = []
            if pid_data.get("Seccomp", False):
                features.append("seccomp")
            if pid_data.get("root", "/") != "/":
                features.append("chroot")

            result = ""
            if features:
                result = self.getColored("|".join(features))

        elif ProcColumns.isCap(column):
            # handle any capability set

            # no capabilities and all capabilities are common cases
            boring_caps = [0, 274877906943]
            all_uids_are_root = all_uids_equal and pid_data["Uid"][0] == 0
            no_uids_are_root = pid_data["Uid"].count(0) == 0
            capabilities = pid_data.get(column_label, None)

            if capabilities == None:
                # e.g. CapAmb on SLE-11
                return ""
            elif all_uids_are_root:
                # is root anyways
                result = ""
            elif not self.m_verbose and capabilities in boring_caps:
                # don't show the boring ones unless on verbose
                result = ""
            else:
                # show actual capability labels
                tmp_cap_list = self.m_cap_translator.getCapStrings(capabilities)
                new_cap_list = []
                if no_uids_are_root:
                    for tmp_cap in tmp_cap_list:
                        new_cap_list.append(termcolor.colored(tmp_cap, color=cap_color))
                result = "\n".join(new_cap_list)

        elif column in (ProcColumns.executable, ProcColumns.parameters):
            # split up process command lines to avoid excess length columns
            max_len = 40
            text = pid_data[column_label]
            result = textwrap.fill(text, width = max_len)

        elif column == ProcColumns.open_fds:
            if "open_files" not in pid_data:
                result = "RACE_CONDITION"
            elif not self.m_show_fds:
                result = len(pid_data["open_files"])
            else:
                # in case we print the full fds we add a newline after each process to make it a bit more readable
                proc_wrapper = self.m_proc_wrapper
                result = str(proc_wrapper.getFileDescriptorsForPid(pid)) + "\n"
        elif column == ProcColumns.umask:
            result = "{0:o}".format(pid_data['Umask']).rjust(4, '0') if 'Umask' in pid_data else ''

        elif column in pid_data:
            # take data as is
            result = pid_data[column_label]

        elif column == ProcColumns.namespace:
            # check if namespaces differ from parent one
            result = ''
            if not self.m_used_namespaces:
                self.collectUsedNamespaces()
            for index in range(0, len(self.m_used_namespaces)):
                ns = self.m_used_namespaces[index]
                ns_type = ns[1]['type']
                # check for pid namespace
                if self.m_ns_pid:
                    real_pid = self.m_ns_pid[pid]
                    real_parent = self.m_ns_pid[pid_data["parent"]]
                else:
                    real_pid = pid
                    real_parent = pid_data["parent"]
                if real_pid in ns[1]['pids'] and not real_parent in ns[1]['pids']:
                    val = "{}({})".format(ns[1]['nbr'], ns[1]['type'])
                    result = '\n'.join((result, val))

        else:
            raise Exception("Unexpected column " + column_label + " encountered")

        return result

    def getColored(self, a_string):
        """
        Simple wrapper to the coloring function, unless the output is piped into
        another tool, like less or grep.
        """

        result = a_string
        if self.m_have_tty:
            result = termcolor.colored(a_string, "red")
        return result

    def recursiveProcTree(self, children_provider, pid, level, recursive):
        """
        Constructs a list of tuples (pid, level) that describes the process
        tree and which indentation level should be applied each entry.
        """

        self_row = (pid, level)
        children_rows = []

        # if current pid has children and unless the user does not explicitly
        # want them printed

        children = children_provider(pid)

        if recursive and children:
            for child_pid in sorted(children):
                children_rows += self.recursiveProcTree(
                    children_provider,
                    child_pid,
                    level + 1,
                    recursive
                )

        return [self_row] + children_rows

    def generateTable(self, column_headers, proc_tree, table_data, prefix='+---'):
        """
        Generates the actual table lines from the input parameters.

        :param list column_headers: A list of the column header labels
        :param list proc_tree: A list of (pid, indent_level) tuples,
            describing the process tree.
        :param dict table_data: A dictionary containing the table field values
        of the form {
            "column heading": { 4711:
                <data>,
            },
        }
        :param string prefix: The prefix to post in front of each pid.
        """
        indent = self.m_indentation_width * " "
        result_table = [[
            ProcColumns.getLabel(col) for col in column_headers
        ]]

        for pid, level in proc_tree:
            line = []
            for column in column_headers:
                if column == ProcColumns.pid:
                    tmp = (level * indent) + prefix + str(pid)
                else:
                    tmp = table_data[column][pid]
                line.append(tmp)

            result_table.append(line)
            result_table += self.generateThreadWarningsForPid(pid, column_headers, indent*level)

        return result_table

    def printProcessTree(self):
        """Prints a complete process tree according to currently active view
        settings."""

        def excludeProcColumn(column):
            """Returns a boolean whether the given column index should be
            excluded from the view according to command line arguments."""
            label = ProcColumns.getLabel(column)

            if label in self.m_excluded:
                print(label, "excluded")
                return True
            elif self.m_included and label not in self.m_included:
                print(label, "not included")
                return True

            return False

        proc_wrapper = self.m_proc_wrapper

        num_procs = proc_wrapper.getProcessCount()
        logging.info("There are {} processes running on {}.".format(
            num_procs,
            self.m_node_label
        ))

        all_pids = proc_wrapper.getAllPids()
        children_provider = proc_wrapper.getChildrenForPid
        parents = proc_wrapper.getParents()

        column_headers = ProcColumns.getAll()
        table = {}
        to_remove = set()
        for column in column_headers:
            if column == ProcColumns.pid:
                continue

            table[column] = {}
            for pid in all_pids:
                table[column][pid] = self.getColumnValue(column, pid)

            column_values = list(table[column].values())
            if len(set(column_values)) == 1 and column_values[0] == "":
                to_remove.add(column)
            elif excludeProcColumn(column):
                to_remove.add(column)
                continue

        # These values are generally uninteresting
        to_remove.add(ProcColumns.cap_ambient)
        to_remove.add(ProcColumns.cap_bnd)

        # if we show the threads there's no need to show the count
        if self.m_show_threads:
            to_remove.add(ProcColumns.threads)

        # remove the umask column if no data is available
        if len(table[ProcColumns.umask]) < 1 or table[ProcColumns.umask].values()[0] == '':
            to_remove.add(ProcColumns.umask)

        if not self.m_show_params:
            to_remove.add(ProcColumns.parameters)

        # Remove empty columns since they only take up unnecessary space
        for empty_column in to_remove:
            column_headers.remove(empty_column)

        level = 0
        prefix = '+---'

        # proc_tree
        # [ [1,0], [400,1], [945,1], [976,2], [1437, 3], ... ]
        proc_tree = []
        if self.m_pid_filter:
            recursive = self.m_show_filter_children
            for pid in self.m_pid_filter:
                if self.m_show_filter_parents:
                    pid = parents[pid]

                if pid not in all_pids:
                    raise squinnie.errors.ScannerError(
                        "There is no process that has pid {} on this node.".format(
                            pid
                        )
                    )

                proc_tree += self.recursiveProcTree(
                    children_provider,
                    pid,
                    level,
                    recursive
                )
        elif self.m_uid_filter >= 0 or self.m_gid_filter >= 0:
            proc_tree = [
                (pid, 0) for pid in all_pids
                if ((not self.m_uid_filter) or proc_wrapper.processHasUid(pid, self.m_uid_filter)) and
                   ((not self.m_gid_filter) or proc_wrapper.processHasGid(pid, self.m_gid_filter))
            ]
            prefix = ''
        else:
            root_pids = []
            if self.m_ns_pid:
                # more than one root pid could exist, if a process
                # joins into the pid namespace
                for parent in parents.items():
                    if parent[1] == 0:
                        root_pids.append(parent[0])
            else:
                root_pids = [1]
            if self.m_show_kthreads:
                # for kernel threads PID2 is the root
                root_pids.append(2)

            for pid in root_pids:
                proc_tree += self.recursiveProcTree(
                    children_provider,
                    pid,
                    level,
                    True
                )

        table = self.generateTable(column_headers, proc_tree, table, prefix=prefix)

        table = terminaltables.AsciiTable(table)

        # Do not use any borders at all
        table.outer_border = False
        table.inner_column_border = False
        table.inner_heading_row_border = False

        #set running time column to be right-aligned
        table.justify_columns[table.table_data[0].index("running time")] = 'right'

        print(table.table)

    def printFilesystemTable(self):

        table = self.getFilesystemTable()

        if len(table) == 0:
            print("Nothing was found matching the given filters.")
            return

        nm_lambda = lambda t: 'magenta' if t == '(unknown)' else None

        formatter = TablePrinter(columns=[
            Column('permissions', [], self.m_have_tty),
            Column('type', [lambda t: 'red' if t.startswith('ukn') else None], self.m_have_tty),
            Column('user', [nm_lambda], self.m_have_tty),
            Column('group', [nm_lambda], self.m_have_tty),
            Column('capabilities', [lambda x: "red"], self.m_have_tty),
            Column('path', [], self.m_have_tty)
        ], data=table, include=self.m_included, exclude=self.m_excluded)

        formatter.writeOut()

    def _getTermSize(self):
        """Returns the size of the terminal as a pair of (cols, rows)."""
        # starting with py3.3 there's also shutil.get_terminal_size()
        res = subprocess.check_output(
            ["stty", "size"], close_fds=True, shell=False
        )
        return tuple(reversed([int(part) for part in res.decode().split()]))

    def createFsQuery(self, args):
        # clear query filters
        self.m_fsquery.clear()

        if args.special_bits:
            self.m_fsquery.filterForSpecialBits()

        if args.capabilities:
            self.m_fsquery.filterForCapabilities()

        if self.m_uid_filter >= 0:
            self.m_fsquery.filterForUid(self.m_uid_filter)

        if self.m_gid_filter >= 0:
            self.m_fsquery.filterForGid(self.m_gid_filter)

        # parser.add_argument("--filemode-max", type=octint, default=-1, help=description)\
        # file mode

        if args.has_mode > 0:
            self.m_fsquery.filterForUmask(args.has_mode)

        if args.filemode_min > 0:
            self.m_fsquery.exclusiveUmask(args.filemode_min)

        if args.filemode_max > 0:
            self.m_fsquery.filterFilesWithBits(args.filemode_max)

        if args.filemode > 0:
            self.m_fsquery.filterFileMode(args.filemode)

        if args.numeric:
            self.m_show_numeric = True

        if args.type is not None:
            # files are stored in the database with the type '-', but 'f' is more intuitive to the user
            if args.type == "f":
                args.type = "-"
            self.m_fsquery.filterForType(args.type)

    def setExcludeInclude(self, args):
        if args.cols and len(args.cols) > 0:
            self.m_included = args.cols.split(",")

        if args.exclude and len(args.exclude) > 0:
            self.m_excluded = args.exclude.split(",")

    def printSystemVIPC(self):
        sysv = self.m_daw_factory.getSysVIpcWrapper()

        # type\perms\user\group\key\id\ctime\cpid\atime\apid

        formatter = TablePrinter(columns=[
            Column('type', [], self.m_have_tty),
            Column('perms', [
                lambda v: 'magenta' if v[-2] == '0' else None,
                lambda v: 'red' if v[-1] != '0' else None
            ], self.m_have_tty),
            Column('user', [], self.m_have_tty),
            Column('group', [], self.m_have_tty),
            Column('key', [], self.m_have_tty),
            Column('id', [], self.m_have_tty),
            Column('creation-time', [], self.m_have_tty),
            Column('creator-pid', [], self.m_have_tty),
            Column('last-access-time', [], self.m_have_tty),
            Column('last-access-pid', [], self.m_have_tty),
        ], data=sysv.getFormattedData(), include=self.m_included, exclude=self.m_excluded)
        formatter.writeOut()

    def generateThreadWarningsForPid(self, pid, column_headers, indent):
        proc_wrapper = self.m_proc_wrapper
        data = proc_wrapper.getProcessInfo(pid)

        comparison_keys = {  # eff, inh, prm
            ProcColumns.executable: 'cmdline',
            ProcColumns.user: "Uid",
            ProcColumns.groups: "Gid",
            ProcColumns.cap_inherit: "CapInh",
            ProcColumns.cap_eff: "CapEff",
            ProcColumns.cap_perm: "CapPrm"
        }
        output = []

        for tid, tdata in data['threads'].items():
            # we don't show the main thread as it's attributes are the same as those of the process
            if int(tid) == int(pid):
                continue

            # check if any values are different
            highlight_cols = []
            for column, key in comparison_keys.items():
                if data[key] != tdata[key]:
                    highlight_cols.append(column)

            # if so, output the thread
            if len(highlight_cols) > 0 or self.m_show_threads:
                line = []
                for column in column_headers:
                    tmp = ''  # values which are not pid or not compared are ignored.
                    if column == ProcColumns.pid:
                        tmp = termcolor.colored(indent + 't---' + str(tid), "cyan")
                    elif column in comparison_keys.keys():
                        tmp = self.formatColumnValue(column, tid, tdata, cap_color='magenta')
                        if column in highlight_cols:
                            tmp = termcolor.colored(tmp, 'magenta')
                        else:  # unimportant values are not shown
                            tmp = termcolor.colored('*', 'white')

                    line.append(tmp)
                output.append(line)

        return output

    def setShowThreads(self, show_threads):
        self.m_show_threads = show_threads

    def hideEmptyColumns(self, data, cnames):
        """
        Goes through data and adds empty columns to self.m_excluded
        :list data: twodimensional list to filter
        :list cnames: contains column-names in order
        """
        empty = [0]*len(cnames)
        for iface in data:
            for index in range(0, len(iface)):
                if iface[index] == '':
                    empty[index] += 1
        for index in range(0, len(empty)):
            if empty[index] == len(data):
                self.m_excluded.append(cnames[index])

    def printFilteredColumns(self, output, column_names):
        """
        Remove empty columns before printing
        :list column_names: the column names
        :list output: the data to print
        """
        self.hideEmptyColumns(output, column_names)
        columns = []
        for name in column_names:
            columns.append(Column(name, [], self.m_have_tty))
        formatter = TablePrinter(columns, data=output,
                include=self.m_included, exclude=self.m_excluded)
        formatter.writeOut()

    def printNetworkInterfaces(self, data=None):
        # list for keys in data-dictionary, order must be matching the
        # column_name's below
        identifier = [
            'ifindex', 'iface', 'operstate', 'mtu', 'flags', 'type',
            'uevent', 'address', 'ipv4', 'ipv6', 'attached'
        ]
        column_names = [
            'ifindex', 'name', 'operational_status', 'mtu',
            'flags', 'device_type', 'uevent_DEVTYPE', 'MAC_address',
            'IPv4_address', 'IPv6_address', 'attached'
        ]
        if not data:
            nwinterfaces = self.m_daw_factory.getNwIfaceInfoWrapper()
            data = nwinterfaces.getAllNwIfaceData()
        output = self.m_nwiface_translator.getFormattedData(data,
                                                       identifier)
        self.printFilteredColumns(output, column_names)

    def dictKeyIntify(self, overwrite, data):
        """
        Small converter for converting dictionary keys back to
        integers.
        :list overwrite: tuples with (original name, result name) pairs
        :dict data: the data with subdictionaries with wrong keytypes
        """
        res = {}
        for intify in overwrite:
            res[intify[1]] = {}
            for str_val in data[intify[0]].items():
                res[intify[1]][int(str_val[0])] = str_val[1]
        return res

    def printNamespaces(self):
        # namespace data keys and their associated column labels
        columns = [
            ('nbr', 'number'),
            ('ns', 'namespace'),
            ('type', 'type'),
            ('nprocs', 'number of processes'),
            ('pid', 'pid'),
            ('uid', 'user'),
            ('command', 'command')
        ]
        labels = [ c[1] for c in columns]
        if not self.m_used_namespaces:
            self.collectUsedNamespaces()
        accounts = self.getAccountHelper()
        output = []
        pid_filter = self.m_pid_filter
        for ns_inode, ns_info in self.m_used_namespaces:
            column = []
            if pid_filter:
                valid_col = True
                for filtered_pid in pid_filter:
                    if not filtered_pid in ns_info['pids']:
                        valid_col = False
                        break
                if not valid_col:
                    continue
            for index in range(0, len(columns)):
                col_key = columns[index][0]
                if col_key == "nbr":
                    column.append(str(ns_info[col_key]))
                elif col_key == 'ns':
                    column.append(ns_inode)
                elif col_key == "type":
                    column.append(str(ns_info[col_key]))
                elif col_key == "nprocs":
                    column.append(str(len(ns_info['pids'])))
                elif col_key == 'pid':
                    column.append(str(ns_info['pids'][0]))
                elif col_key == 'uid':
                    user = accounts.getNameForUid(
                            ns_info['uid'], default="unknown"
                    )
                    column.append(user)
                elif col_key == 'command':
                    col_pid = ns_info['pids'][0]
                    proc_data = self.m_proc_wrapper.getProcessInfo(col_pid)
                    cmdline = proc_data["cmdline"].replace('\x00', ' ').strip()
                    column.append(cmdline)
            output.append(column)
        self.printFilteredColumns(output, labels)
        # start namespace-internal printing
        data = self.m_deep_namespace_data
        for entry in data.items():
            for inode in entry[1].items():
                element = []
                # get column of current namespace
                col = []
                for val in output:
                    if inode[0] == val[1]:
                        col = val
                        break
                if not col:
                    # pid-filter probably removed column
                    continue
                for index in range(0, len(self.m_used_namespaces)):
                    if self.m_used_namespaces[index][0] == inode[0]:
                        element = [index, self.m_used_namespaces[index]]
                        break
                if not element:
                    raise ValueError(
                            'namespace not included in namespace-list!'
                    )
                printstr = "for namespace {}(PID {}):".format(col[0], col[4])
                if entry[0] == 'net':
                    print("Network scan {}".format(printstr))
                    self.printNetworkInterfaces(data=inode[1])
                elif entry[0] == 'uts':
                    print("Host- and Domainname {}".format(printstr))
                    print("Hostname: {}".format(inode[1][0]))
                    print("Domainname: {}".format(inode[1][1]))
                elif entry[0] == 'user':
                    if not inode[1]['gid'] or not inode[1]['uid']:
                        # empty set
                        continue
                    col_names = ["startvalue inside namespace",
                        "startvalue outside namespace(parent view)",
                        "length"
                    ]
                    for curr_type in ["uid", "gid"]:
                        curr_output = inode[1][curr_type]
                        print("{} mapping for {}".format(curr_type, printstr))
                        self.printFilteredColumns(curr_output, col_names)
                elif entry[0] == 'pid' and pid_filter:
                    if not inode[1]['pids_info']:
                        # no internal process tree available
                        continue
                    # pid filter interfers if set globally
                    self.m_pid_filter = None
                    ext_pids = element[1][1]['pids']
                    overwrite = [("status", "proc_data"),
                            ("parents", "parents")
                    ]
                    data_dict = self.dictKeyIntify(overwrite,
                            inode[1]['pids_info']
                    )
                    # since our standart ProcWrapper uses the collected
                    # process data from standart perspective, we need
                    # to customize this to fit our needs for an inside
                    # view of the pid-namespace
                    pid_handler = LocalFactory(data_dict).getProcWrapper()
                    print("PID mappings for {}".format(printstr))
                    # set variables for pid-ns mode
                    if len(ext_pids) != len(data_dict["proc_data"]):
                        raise ValueError(
                                "Pid mapping of pid namespace {} is invalid!"
                                .format(inode[0])
                    )
                    # create pid-ns mapping dict
                    self.m_ns_pid = {0 : 0}
                    pids_sorted = sorted(data_dict["proc_data"])
                    for pid_index in range(0, len(pids_sorted)):
                        self.m_ns_pid[
                                pids_sorted[pid_index]
                        ] = ext_pids[pid_index]
                    self.m_proc_wrapper = pid_handler
                    self.printProcessTree()

class TablePrinter(object):
    """This class prints a table to the terminal"""

    def __init__(self, columns, data, include=[], exclude=[]):
        """
        Creates a new object of type table.
        :param columns: All the columns. This should be Column objects.
        :param data: The data to print. Must be a two dimensional array ([lines][cols]) of stuff to print.
        :param include: What columns to include. Will not override excluded ones.
        :param exclude: What columns to exclude.
        """
        self.m_columns = columns
        self.m_exclude = exclude
        self.m_include = include
        self.m_data = data
        self.m_col_len = self._determineMaxLengthForColumns()

    def makeLineStr(self, line):
        """
        Creates a colored (if enabled) string for the given dataset.
        """

        str = []

        for i in range(len(self.m_columns)):
            name = self.m_columns[i].name

            # check if the column is on the whitelist (if it is not empty) and not on the black list
            if (len(self.m_include) > 0 and name not in self.m_include) or name in self.m_exclude:
                continue

            str.append(self.m_columns[i].getValue(line[i], padding=self.m_col_len[i]))

        return " ".join(str).rstrip()

    def writeOut(self):
        self._writeHeaders()

        for i in range(len(self.m_data)):
            print(self.makeLineStr(self.m_data[i]))

    def _writeHeaders(self):
        hd = []
        for i in range(len(self.m_columns)):
            name = self.m_columns[i].name

            # check if the column is on the whitelist (if it is not empty) and not on the black list
            if (len(self.m_include) > 0 and name not in self.m_include) or name in self.m_exclude:
                continue
            hd.append(name.ljust(self.m_col_len[i]))

        print(" ".join(hd))

    def _determineMaxLengthForColumns(self):
        maxlen = [0] * len(self.m_columns)

        for i in range(len(self.m_data)):
            row = self.m_data[i]

            try:
                for k in range(len(self.m_columns)):
                    if maxlen[k] < len(row[k]):
                        maxlen[k] = len(row[k])
            except IndexError as e:
                exit("Error, looks like the amount of elements given in columns and data differs:\n{}".format(e))

        for k in range(len(self.m_columns)):
            if maxlen[k] < len(self.m_columns[k].name):
                maxlen[k] = len(self.m_columns[k].name)

        return maxlen


class Column(object):
    """This class represents a column for printing via TablePrinter"""

    def __init__(self, name, filter_functions=[], enable_color=True):
        """
        :param name: The title of the column
        :param filter_functions: A function to determine the color of the output. Should return a string describing a
        color in case of colored output (e.g. "red") or None if no color should be applied. The last filter function to
        return a color will be used. The only input argument will be the data.
        """
        self.m_filter_funtions = filter_functions
        # no m_ as this is public
        self.name = name
        self.m_colored = enable_color

    def addFilterFunction(self, fn):
        self.m_filter_funtions.append(fn)

    def getValue(self, data, padding=0):
        """Returns a colored string for printing if a lambda matches and there is a terminal used (determined by
        constructor argument) or the data otherwise."""
        if not self.m_colored:
            return data

        # go through all filter FNs in reverse to find a given color
        for i in range(len(self.m_filter_funtions)-1, -1, -1):
            color = self.m_filter_funtions[i](data)

            # if a color is found, we're done :)
            if color is not None:
                return termcolor.colored(str(data).ljust(padding), color)

        return data.ljust(padding)

