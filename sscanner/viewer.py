#!/usr/bin/env python2
# vim: ts=4 et sw=4 sts=4 :

# security scanner - scan a system's security related information
# Copyright (C) 2017 SUSE LINUX GmbH
#
# Author:     Benjamin Deuter
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
from __future__ import print_function
from __future__ import with_statement
import sys
import os
import argparse
import stat
import subprocess
# Local modules.
import sscanner.cap_translator as cap_translator
import sscanner.helper as helper
import sscanner.file_mode as file_mode
import sscanner.errors
from sscanner.types import ProcColumns

pickle = helper.importPickle()

# foreign modules
try:
    import terminaltables
    import termcolor
except ImportError as e:
    helper.missingModule(ex=e)


class Viewer(object):
    """This class implements the various view operations on node data."""

    def __init__(self):

        self.m_node_data = None
        self.m_verbose = False
        self.m_have_tty = os.isatty(sys.stdout.fileno())
        self.m_show_fds = False
        self.m_show_params = False
        self.m_pid_filter = []
        self.m_show_filter_parents = False
        self.m_show_filter_children = False
        self.m_show_kthreads = False
        self.m_indentation_width = 4

        cap_json = os.path.sep.join([
            os.path.abspath( os.path.dirname(__file__) ),
            os.path.pardir,
            "etc",
            "cap_data.json"
        ])
        self.m_cap_translator = cap_translator.CapTranslator(cap_json)

    def activateSettings(self, args):
        """Activates the settings found in the given argparse.Namespace
        object."""
        self.setVerbose(args.verbose)
        self.setShowFds(args.fd)
        self.setShowParams(args.params)
        self.setShowKthreads(args.kthreads)
        self.setShowFilterChildren(args.children)
        self.setShowFilterParents(args.parent)

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
        else:
            # process tree view
            self.printProcessTree()

    @classmethod
    def addParserArguments(cls, parser):
        """Adds the viewer specific command line arguments to the given
        argparse.ArgumentParser object."""
        # this is for reuse in the main security_scanner script.

        description = "Show parameters from the process's cmdline entry."
        parser.add_argument("--params", action="store_true", help=description)

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

        description = "View all files on the file system, including their permissions."
        parser.add_argument("--filesystem", action="store_true", help=description)


    def loadData(self, node_dump):
        """Load node data to operate on from the given file."""

        try:
            self.m_node_data = helper.readPickle(path = node_dump)
        except Exception as e:
            if isinstance(e, EOFError):
                # on python2 no sensible error string is contained in EOFError
                e = "Premature end of file"
            raise sscanner.errors.ScannerError(
                "Failed to load node data from {}: {}".format(node_dump, str(e))
            )

        assert len(self.m_node_data.keys()) == 1
        self.m_node_label = next(iter(self.m_node_data.keys()))
        self.m_node_data = next(iter(self.m_node_data.values()))

    def setData(self, label, node_data):
        """Use the given node data structure to operate on."""
        self.m_node_label = label
        self.m_node_data = node_data

    def setVerbose(self, verbose):
        self.m_verbose = verbose

    def setShowFds(self, show):
        """Also show per process file descriptor info."""
        self.m_show_fds = show

    def setShowParams(self, show):
        """Also show process parameters in an extra column."""
        self.m_show_params = show

    def addPidFilter(self, pid):
        """Don't show all PIDs but just the given PID in the table.
        Accumulates."""
        self.m_pid_filter.append(pid)

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

    def printFileDescriptors(self):
        """Prints all file descriptors of all processes found in the current
        data set."""

        all_pids = self.m_node_data["proc_data"].keys()

        for pid in sorted(all_pids):
            info = self.m_node_data["proc_data"][pid]
            open_file_count = len(info["open_files"])

            # Hide the process if it has no open files
            # But always show all processes on -v
            if open_file_count > 0 or self.m_verbose:
                list_str = self.getListOfOpenFileDescriptors(info)
                print("{} (pid: {})".format(info["executable"], pid))
                print("----")
                print(list_str)
                print("")

    def getFileProperties(self, filename):
        """Returns the properties of a given file path in the file system. Or
        an empty dictionary on failure."""
        tokens = filename[1:].split(os.path.sep)
        filesystem = self.m_node_data['filesystem']['subitems']
        try:
            while True:
                t = tokens.pop(0)
                if tokens:
                    filesystem = filesystem[t]["subitems"]
                else:
                    # last node, get the property
                    return filesystem[t]["properties"]
        except KeyError:
            # file not found
            pass

        return {}

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

    def getFilesystemTable(self, cur_path = None, cur_node = None):
        """
        Recursively constructs and returns list of strings that describes the
        complete file system structure rooted at cur_path/cur_node.

        :param str cur_path: The current path string which needs to correspond
        to `cur_node`.
        :param dict cur_node: The current dictionary entry from
        self.m_node_data['filesystem'] that corresponds to `cur_path`
        """

        if not cur_node and not cur_path:
            cur_node = self.m_node_data['filesystem']
            cur_path = '/'
            # iterate just over the root node for the start
            items = ("/", cur_node),
        elif not cur_node or not cur_path:
            raise Exception("Need either both or none of `cur_node` and `cur_path`")
        else:
            # iterate over all sub-items
            items = sorted(cur_node.items())

        uid_name = self.m_node_data["uid_name"]
        gid_name = self.m_node_data["gid_name"]

        ret = []

        for name, info in items:
            base_path_file = os.path.join(cur_path, name)
            props = info["properties"]

            if not props:
                # some file we couldn't get properties for
                ret.append(["???", base_path_file, "???", "?", "?", "?"])
                continue

            perm_str = file_mode.getModeString(props["st_mode"])
            file_type = file_mode.getTypeLabel(props["st_mode"])

            if props["st_uid"] not in uid_name:
                user  = "!USERERROR!"
            else:
                user  = uid_name[props["st_uid"]]

            if props["st_gid"] not in gid_name:
                group = "!GROUPERROR!"
            else:
                group = gid_name[props["st_gid"]]

            caps = self.m_cap_translator.getCapStrings(props["caps"])
            cap_str = "|".join(caps)

            ret.append(
                [perm_str, base_path_file, file_type, user, group, cap_str]
            )

            subitems = info.get("subitems", None)
            if subitems:
                # descend into the next node, depth-first
                ret += self.getFilesystemTable(base_path_file, subitems)

        return ret

    def inodeToIdentifier(self, _type, inode):
        """
        Returns a human readable string describing the given node number.

        This is helpful for pseudo files found in /proc/<pid>/fd, that for
        some types of files contain the inode number which can be looked up in
        other data structures.

        :param str _type: The type of the inode like "socket"
        :param int inode: The inode number to lookup.
        """

        if _type != "socket":
            raise Exception("Can only translate socket inodes for now")

        result = []
        for transport_protocol in ["tcp", "tcp6", "udp", "udp6", "unix"]:
            transport_dict = self.m_node_data.get(transport_protocol, {})
            if not transport_dict:
                continue
            inode_entry = transport_dict.get(str(inode), -1)

            if inode_entry == -1:
                continue

            # a named unix domain socket
            if transport_protocol == "unix":
                if inode_entry == "": # unnamed unix domain socket
                    inode_entry = "<anonymous>"
                else: # named or abstract unix domain socket
                    # TODO: this lookup doesn't work for abstract sockets
                    props = self.getFileProperties(inode_entry)
                    # TODO: this else branch makes no sense
                    if props:
                        st_mode = props['st_mode']
                        permissions = file_mode.getModeString(st_mode)
                    else:
                        permissions = "!PERMERROR"
                    inode_entry = "{} (named socket file permissions: {})".format(
                        inode_entry, permissions
                    )
            else: # TCP or UDP socket with IP address and port
                # TODO: state flags are missing in the data to determine
                # listening sockets for tcp
                # TODO: also include IP addresses for IPv4/v6 respectively
                # using python socket formatting functions
                inode_entry = int(inode_entry[0][1], 16) # port of the local ip

            result.append("{}:{}".format(transport_protocol, inode_entry))

        result = "|".join(result)

        if result:
            return result
        else:
            return "<port not found, inode: {:>15}>".format(inode)

    def getPseudoFileDesc(self, pseudo_label):
        """
        Returns a descriptive, formatted string for the given ``pseudo_label``
        which is the symlink content for pseudo files in /proc/<pid>/fd.
        """

        # Convert fds to more easy-to-read strings

        # this is a string like "<type>:<value>", where <value> is either an
        # inode of the form "[num]" or a subtype field like "inotify".
        _type, value = pseudo_label.split(':', 1)
        value = value.strip("[]")

        if _type == "pipe":
            # TODO: include to which process this pipe is connected to
            result = "{} : {:>10}".format(_type, value)
        elif _type == "socket":
            result = "{} : {:>10}".format(
                _type, self.inodeToIdentifier(_type, int(value))
            )
        elif _type == "anon_inode":
            result = "{} : {}".format(_type, value)
        else:
            raise Exception("Unexpected pseudo file type " + _type)
        return result

    def getListOfOpenFileDescriptors(self, pid_data):
        """
        Get all open file descriptors as a list of strings.

        :param dict pid_data: the info dictionary of the PID for which to get the
        info.
        """

        real_files = []
        pseudo_files = []

        for fd, info in pid_data["open_files"].items():

            symlink = info["symlink"]

            flags = file_mode.getFdFlagLabels(info["file_flags"])
            #TODO: This should be in the DAW
            file_perm = {
                "Uid": (info["file_perm"] & stat.S_IRWXU) >> 6,
                "Gid": (info["file_perm"] & stat.S_IRWXG) >> 3,
                "other": (info["file_perm"] & stat.S_IRWXO) >> 0,
            }
            perms_octal = ''.join(
                [ str(file_perm[key]) for key in ('Uid', 'Gid', 'other') ]
            )

            # TODO: this is a bug, the symlink may contain a colon even if it
            # is a real file. Only if it is a broken symlink we can assume
            # this.
            is_pseudo_file = ":" in symlink

            # pseudo files: sockets, pipes, ...
            if is_pseudo_file:

                type, inode = symlink.split(':', 1)
                line = self.getPseudoFileDesc(symlink)

                if self.m_verbose:
                    line = "{:>5}: ".format(fd) + line
                if type == "socket":
                    line = "{} (permissions: {})".format(line, perms_octal)
                if flags:
                    line = "{} (flags: {})".format(line, "|".join(flags))

                pseudo_files.append(line)
            else:
                # real files on disk

                file_identity = info["file_identity"]

                color_it = False
                for uid_type in pid_data["Uid"]:

                    user_identity = {
                        "Uid":uid_type,
                        "Gid_set":pid_data["Gid"],
                    }

                    if not file_mode.canAccessFile(
                        user_identity,
                        file_identity,
                        file_perm
                    ):
                        color_it = True

                line = symlink
                if color_it:
                    line = self.getColored(line)

                if self.m_verbose:
                    line = "{:>5}: ".format(fd) + line
                # TODO: also add ownership information
                line = "{} (permissions: {})".format(line,
                        perms_octal)
                if flags:
                    line = "{} (flags: {})".format(line, "|".join(flags))
                real_files.append(line)

        all_strs = sorted(real_files) + sorted(pseudo_files)

        return "\n".join(all_strs)

    def getColumnValue(self, column, pid):
        """
        Get the string value for the given table ``column`` of the given
        process with ``pid``.
        """

        pid_data = self.m_node_data["proc_data"][pid]
        uid_name = self.m_node_data["uid_name"]
        gid_name = self.m_node_data["gid_name"]

        if "Uid" not in pid_data.keys():
            return ""

        column_label = ProcColumns.getLabel(column)

        # check whether a process runs with surprising saved/effective uid/gid
        all_uids_equal = len(set(pid_data["Uid"])) == 1
        all_gids_equal = len(set(pid_data["Gid"])) == 1

        if column == ProcColumns.user:
            user_set = set()

            for item in set(pid_data["Uid"]):
                if self.m_verbose:
                    user_label = "{}({})".format(uid_name[item], item)
                else:
                    user_label = uid_name[item]
                user_set.add(user_label)

            result = "|".join(str(x) for x in user_set)
            if not all_uids_equal:
                result = self.getColored(result)

        elif column == ProcColumns.groups:
            # merge the main gid and the auxiliary group ids
            groups_set = set(pid_data["Gid"]) | set(pid_data["Groups"])
            groups = set()

            for item in groups_set:
                if self.m_verbose:
                    group_label = "{}({})".format(gid_name[item], item)
                else:
                    group_label = gid_name[item]
                groups.add(group_label)
            result = "|".join([str(x) for x in groups])
            if not all_gids_equal:
                result = self.getColored(result)

        elif column == ProcColumns.features:
            features = []
            if pid_data["Seccomp"]:
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
            capabilities = pid_data[column_label]

            if all_uids_are_root:
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
                        new_cap_list.append(self.getColored(tmp_cap))
                result = "\n".join(new_cap_list)

        elif column in (ProcColumns.executable, ProcColumns.parameters):
            # don't show excess length parameters, only a prefix
            max_len = 40
            cmdline = pid_data[column_label]
            cmdline_chunks = [cmdline[i:i+max_len] for i in range(0, len(cmdline), max_len)]
            result = "\n".join(cmdline_chunks)

        elif column == ProcColumns.open_fds:
            if "open_files" not in pid_data:
                result = "RACE_CONDITION"
            elif not self.m_show_fds:
                result = len(pid_data["open_files"])
            else:
                result = self.getListOfOpenFileDescriptors(pid_data)

        elif column in pid_data:
            # take data as is
            result = pid_data[column_label]
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

    def recursiveProcTree(self, children, pid, level, recursive):
        """
        Constructs a list of tuples (pid, level) that describes the process
        tree and which indentation level should be applied each entry.
        """

        self_row = (pid, level)
        children_rows = []

        # if current pid has children and unless the user does not explicitly
        # want them printed

        if recursive and pid in children.keys():
            for child_pid in sorted(children[pid]):
                children_rows += self.recursiveProcTree(
                    children,
                    child_pid,
                    level+1,
                    recursive
                )

        return [self_row] + children_rows

    def generateTable(self, column_headers, proc_tree, table_data):
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
        """
        indent = self.m_indentation_width * " "
        result_table = []
        result_table.append([
            ProcColumns.getLabel(col) for col in column_headers
        ])

        for pid, level in proc_tree:
            line = []
            for column in column_headers:
                if column == ProcColumns.pid:
                    tmp = ( level * indent ) + "+---" + str(pid)
                else:
                    tmp = table_data[column][pid]
                line.append(tmp)

            result_table.append(line)

        return result_table

    def printProcessTree(self):
        """Prints a complete process tree according to currently active view
        settings."""
        self._assertHaveData()

        num_procs = len(self.m_node_data['proc_data'])
        print("There are {} processes running on {}.".format(
            num_procs,
            self.m_node_label
        ))
        print("")

        all_pids = self.m_node_data["proc_data"].keys()
        children = self.m_node_data["children"]
        parents = self.m_node_data["parents"]

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

        # These values are generally uninteresting
        to_remove.add(ProcColumns.cap_ambient)
        to_remove.add(ProcColumns.cap_bnd)

        if not self.m_show_params:
            to_remove.add(ProcColumns.parameters)

        # Remove empty columns since they only take up unnecessary space
        for empty_column in to_remove:
            column_headers.remove(empty_column)

        level = 0

        # proc_tree
        # [ [1,0], [400,1], [945,1], [976,2], [1437, 3], ... ]
        proc_tree = []
        if self.m_pid_filter:
            recursive = self.m_show_filter_children
            for pid in self.m_pid_filter:
                if self.m_show_filter_parents:
                    pid = parents[pid]

                if not pid in all_pids:
                    raise sscanner.errors.ScannerError(
                        "There is no process that has pid {} on this node.".format(
                            pid
                        )
                    )

                proc_tree += self.recursiveProcTree(
                    children,
                    pid,
                    level,
                    recursive
                )
        else:
            root_pids = [1]
            if self.m_show_kthreads:
                # for kernel threads PID2 is the root
                root_pids.append(2)

            for pid in root_pids:
                proc_tree += self.recursiveProcTree(
                    children,
                    pid,
                    level,
                    True
                )

        table = self.generateTable(column_headers, proc_tree, table)

        table = terminaltables.AsciiTable(table)

        # Do not use any borders at all
        table.outer_border = False
        table.inner_column_border = False
        table.inner_heading_row_border = False

        print(table.table)

    def printFilesystemTable(self):

        table = self.getFilesystemTable()
        width_column_dict = self.buildWidthColumnDict(table)
        if self.m_have_tty:
            term_width = self._getTermSize()[0]
        else:
            term_width = 0
        self.printTableWidthColumnDict(table, width_column_dict, term_width)

    def _getTermSize(self):
        """Returns the size of the terminal as a pair of (cols, rows)."""
        # starting with py3.3 there's also shutil.get_terminal_size()
        res = subprocess.check_output(
            ["stty", "size"], close_fds = True, shell = False
        )
        return tuple(reversed([ int(part) for part in res.decode().split()]))

    def _assertHaveData(self):
        if not self.m_node_data:
            raise Exception("no node data has been loaded")

def main():

    description = "Generate various views from collected node data."
    parser = argparse.ArgumentParser(description=description)

    description = "The input file containing the dumped node data to view."
    parser.add_argument("-i", "--input", required=True, type=str, help=description)

    description = "Print more detailed information."
    parser.add_argument("-v", "--verbose", action="store_true", help=description)

    Viewer.addParserArguments(parser)

    args = parser.parse_args()

    viewer = Viewer()
    viewer.activateSettings(args)
    viewer.loadData(args.input)
    viewer.performAction(args)

if __name__ == "__main__":
    helper.executeMain(main)

