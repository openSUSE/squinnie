# Security Scanner

This is a security scanner that collects security relevant system data from a
local machine, remote host or SUSE Cloud instance. The collected data is
cached in a specific format on disk and can be analysed and viewed according
to command line criteria.

The purpose of the scanner is to:

- identify possible security issues by inspecting privileges of running
  processes, opened file descriptors, files on disk etc.
- allow to navigate through large data sets containing information about a
  running system, for identifying possible interesting interfaces and software
  parts that are worth further investigation.

It allows to look into a running system in a black box fashion. This can be
helpful for reviewing large and complex systems where a code review is not
feasible.

## Installation

The additional python module requirements for this project can be found in the
PIP requirements file `requirements.txt`.

## Structure

The scanner main program is `bin/security_scanner.py`. It's concerned with two
different groups of command line arguments for scanning and viewing. Scanning
is the process of collecting data from one or more hosts. Viewing is the
process of extracting relevant bits of data from an existing data collection
and displaying them in a human readable manner.

## Security Warning

Be aware that collecting the low level system information may be a security
risk in its own right, because sensitive data will be collected and made
accessible in the context of a regular user account.

This scanner is targeted towards analysis of test systems, not for production
environments. If you do want to scan a production system then you should make
sure that the resulting dumps are stored safely to avoid security issues.

At the moment only scans running as the root user are supported. Basically
it would also possible to scan as a non-privileged user. The information
available to the scanner will be very limited then, however.

## Usage

Please see the online help output produced by `./security_scanner.py -h`.

The scanner scans localhost by default, collecting relevant information that
will be cached and displayed, depending on the provided command-line
arguments.

```
# The scanner will cache collected data here
$ mkdir -p /tmp/my_test_scan/

# Main view
$ security_scanner.py --mode ssh --entry root@host -d /tmp/my_test_scan

# Show open file descriptors
$ security_scanner.py --mode ssh --entry root@host -d /tmp/my_test_scan --fd

# Show all files on the filesystem
$ security_scanner.py --mode ssh --entry root@host -d /tmp/my_test_scan/ --filesystem
```

For scanning localhost the scanner program will invoke `sudo` to gain root
privileges. For scanning remote systems `ssh` is utilized and either
interactive authentication or public key authentication will be required to
access them.

The same data cache directory specified with `-d` can be used for different
hosts at the same time. Each host will be stored and looked up by its hostname.

## Advanced Usage

Show which processes run with which capabilities:
```
$ ./security_scanner.py -d /tmp/my_test_scan/ | grep CAP_
```

Show which files on the filesystem have which capabilities set (usually e.g. `/bin/ping`):
```
$ ./security_scanner.py -d /tmp/my_test_scan/ --filesystem --capabilities
```

## SUSE OpenStack Cloud 7

To scan many nodes of a SUSE OpenStack Cloud instance interactively, use:
```
$ ./security_scanner.py -d /tmp/my_test_scan/ -m susecloud -e <ip-of-cloud-admin-node>
```

By default, all nodes are scanned, but only the results of the admin node are shown. To show all, you can use:
```
$ ./security_scanner.py -d /tmp/my_test_scan/ -m susecloud -e <ip-of-cloud-admin-node> -a
```
