# Security Scanner

This is a security scanner that collects security relevant system data from a
local machine, remote host or SUSE Cloud instance. The collected data is
cached in a specific format on disk and can be analysed and viewed according
to command line criteria.

The purpose of the scanner is to:

- identify possibly security issues by inspecting privileges of running
  processess, opened file descriptors, files on disk etc.
- allow to navigate through large data sets containing information about a
  running system, for identifying possible interesting interfaces and software
  parts that are worth further investigation.

## Installation

The additional python module requirements for this project can be found in the
PIP requirements file `requirements.txt`.

## Structure

The scanner program currently consists of a number of independent python
modules that can also be executed in a standalone manner:

- sscanner/dumper.py is responsible for collecting data from local or remote
  hosts.
- sscanner/enrich.py transforms raw data collected via the dumper into a more
  easy to use data structure for purposes of analysis or display.
- sscanner/viewer.py is able to load collected data from disk and display
  various bits of information from it.
- security\_scanner.py combines all these features into a single interface.

## Security Warning

Be aware that collecting the low level system information may be a security
risk in its own right, because sensitive data will be collected and made
accessible in the context of a regular user account.

This scanner is targeted towards analysis of test systems, not for production
environments. If you do want to scan a production system then you should make
sure that the resulting dumps are stored safely to avoid security issues.

## Usage

Please see the online help output produced by `./security_scanner.py -h`.

The scanner scans localhost by default, collecting relevant information that
will be cached and displayed, depending on the provided command-line
arguments.

```
$ mkdir -p /tmp/my_test_scan/                              # The scanner will cache collected data here
$ ./security_scanner.py -d /tmp/my_test_scan/              # Main view
$ ./security_scanner.py -d /tmp/my_test_scan/ --fd         # Show open file descriptors
$ ./security_scanner.py -d /tmp/my_test_scan/ --fd         # Show open file descriptors (cleaner view)
$ ./security_scanner.py -d /tmp/my_test_scan/ --filesystem # Show all files on the filesystem
```

For scanning localhost root privileges are required, because data from all
processes, even root owned ones, will be acquired.

## Advanced Usage

Show which processes run with which capabilities:
```
$ ./security_scanner.py -d /tmp/my_test_scan/ | grep CAP_
```

Show which files on the filesystem have which capabilities set (usually e.g. `/bin/ping`):
```
$ ./security_scanner.py -d /tmp/my_test_scan/ --filesystem | grep CAP_
```

## SUSE OpenStack Cloud 7

To scan many nodes of a SUSE OpenStack Cloud instance iteratively, use:
```
$ ./security_scanner.py -d /tmp/my_test_scan/ -m susecloud -e <ip-of-cloud-admin-node>
```

By default, all nodes are scanned, but only the results of the admin node are shown. To show all, you can use:
```
$ ./security_scanner.py -d /tmp/my_test_scan/ -m susecloud -e <ip-of-cloud-admin-node> -a
```
