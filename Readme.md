# Cloud Scanner

This is a simple scanner that was written while auditing the SUSE OpenStack Cloud 7. This code was written by Benjamin Deuter during an internship at the SUSE Linux GmbH. The current version is maintained on [GitHub](https://github.com/BenjaminDeuter/security-scanner).

## Installation

The requirements for this project can be found in `requirements.txt`. At this point, they are:
- execnet
- terminaltables
- termcolor

## Usage

```
usage: security_scanner.py [-h] [-d DIRECTORY] [-v] [-a] [-m MODE] [-e ENTRY]
                           [--nocache] [--params] [-k] [-p PID] [--children]
                           [--parent] [--fd] [--onlyfd] [--filesystem]

The main cloud scanner, initially built for scanning a SUSE OpenStack Cloud 7
instance. A single wrapper around the functionality of all individual tools.

optional arguments:
  -h, --help            show this help message and exit

general arguments:
  -d DIRECTORY, --directory DIRECTORY
                        The directory all files are cached in. If no value is
                        given here, /tmp/cloud_scanner/ will be used to save
                        files during the execution of the script and then
                        deleted at the end.
  -v, --verbose         Print more detailed information.
  -a, --all             When using a mode that scans multiple hosts, print
                        information from all nodes. By default, only the entry
                        node is printed. This has no effect if the local mode
                        is used.

scan / dump arguments:
  -m MODE, --mode MODE  The mode the scanner should be operating under.
                        Currenly supported are local and susecloud.
  -e ENTRY, --entry ENTRY
                        The host on which crowbar is running. Only valid if
                        using the susecloud mode.
  --nocache             Remove cached files after every run, forcing a re-scan
                        on next execution.

view arguments:
  --params              Show parameters from the executable cmdline variable.
  -k, --kthreads        Include kernel threads. Kernel threads are excluded by
                        default.
  -p PID, --pid PID     Only show data that belongs to the provided pid.
  --children            Also print all the children of the process provided by
                        -p/--pid.
  --parent              Print the parent of the process provided by -p/--pid.
  --fd                  Show all open file descriptors for every process.
  --onlyfd              Show only the open file descriptors in a dedicated
                        view and nothing else.
  --filesystem          View alle files on the file system, including their
                        permissions.
```

`./security_scanner.py` is a global wrapper that makes use of almost all the other Python files.

The scanner scans localhost by default, collecting relevant information that will be cached and displayed, depending on the provided command-line arguments.

```
$ mkdir -p /tmp/my_test_scan/                              # The scanner will cache collected data here
$ ./security_scanner.py -d /tmp/my_test_scan/              # Main view
$ ./security_scanner.py -d /tmp/my_test_scan/ --fd         # Show open file descriptors
$ ./security_scanner.py -d /tmp/my_test_scan/ --fd         # Show open file descriptors (cleaner view)
$ ./security_scanner.py -d /tmp/my_test_scan/ --filesystem # Show all files on the filesystem
```

## Advanced

Show which processes run with which capabilities:
```
$ ./security_scanner.py -d /tmp/my_test_scan/ | grep CAP_
```

Show which files on the filesystem have which capabilities set (usually e.g. `/bin/ping`):
```
$ ./security_scanner.py -d /tmp/my_test_scan/ --filesystem | grep CAP_
```

## SUSE OpenStack Cloud 7

To scan many nodes of a SUSE OpenStack Cloud instance iteratively with one command, use:
```
$ ./security_scanner.py -d /tmp/my_test_scan/ -m susecloud -e <ip-of-cloud-admin-node>
```

By default, all nodes are scanned, but only the results of the admin node are shown. To show all, you can use:
```
$ ./security_scanner.py -d /tmp/my_test_scan/ -m susecloud -e <ip-of-cloud-admin-node> -a
```
