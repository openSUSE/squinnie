Squinnie
=======

This is Squinnie, a security oriented system scanning utility for Linux
systems. It is a terminal program that collects relevant low level system data
from a local machine, remote host or SUSE Cloud instance. The collected data
is cached in an application specific format on disk and can be analysed and
viewed according to command line parameters.

The purpose of Squinnie is to:

- identify possible security issues by inspecting privileges of running
  processes, opened file descriptors, files on disk etc.
- allow to navigate through large data sets containing information about a
  running system, for identifying possible interesting interfaces and software
  parts that are worth further investigation.

Squinnie allows to look into a running system in a black box fashion. This can
be helpful for reviewing large and complex systems where a code review is not
feasible.

Squinnie can highlight certain spots of interest in its different view modes
(e.g. world readable files, unusual capability settings or similar). This
highlighting is currently done by way of terminal colors. These are just
pointers, however. Squinnie will not perform an automatical security analysis
like other tools do (e.g. Lynis). Squinnie rather provides a large data
collection and a means to navigate it that allows a security expert to
interactively dig deeper and uncover possible security issues.

## Installation

The additional python module requirements for this project can be found in the
PIP requirements file `requirements.txt`. These requirements are only for the
host system that runs Squinnie. The target systems scanned by Squinnie don't
require any additional Python modules. For them the only requirement is that a
fairly recent Python 2 interpreter is available.

## Structure

The main program is `bin/squinnie`. It's concerned with two different groups of
command line arguments for scanning and viewing. Scanning is the process of
collecting data from one or more hosts. Viewing is the process of extracting
relevant bits of data from an existing data collection and displaying them in
a human readable manner.

## Data Collection Approach

Squinnie collects a snapshot of data from the target host(s). Most of this
cannot be done in an atomic way i.e. there can be some inconsistencies when
e.g. processes are spawned and ended or files appear and disappear. Thus the
data collection is by design not a perfect information approach. It can make
sense to collect snapshots of data when the target system is in different
states e.g. directly after boot, with an active graphical user session or with
certain server processes being active. This depends much on the target
system's purpose and the desired coverage.

## Security Warning

Be aware that collecting the low level system information may be a security
risk in its own right, because sensitive data will be collected and made
accessible in the context of a regular user account.

This scanner is targeted towards analysis of test systems, not for production
environments. If you do want to scan a production system then you should make
sure that the resulting dumps are stored safely to avoid security issues. Also
note that the scanning process can hurt the target system's performance while
it is taking place, because a lot of I/O is generated and the introspection of
kernel data e.g. via /proc and /sys is bad for caching and locking in the
kernel.

At the moment only scans running as the root user are fully supported.
Basically it would also possible to scan as a non-privileged user. The
information available to the scanner will be very limited then, however.

## Usage

Please see the online help output produced by `./squinnie -h`.

Squinnie scans localhost by default, collecting relevant information that will
be cached and subsequently displayed, depending on the provided command-line
arguments.

```
# Squinnie will cache collected data here
$ mkdir -p /tmp/my_test_scan/

# Main view
$ squinnie --mode ssh --entry root@host -d /tmp/my_test_scan

# Show open file descriptors
$ squinnie --mode ssh --entry root@host -d /tmp/my_test_scan --fd

# Show all files on the filesystem
$ squinnie --mode ssh --entry root@host -d /tmp/my_test_scan/ --filesystem
```

For scanning localhost Squinnie will invoke `sudo` to gain root privileges. For
scanning remote systems `ssh` is utilized and either interactive
authentication or public key authentication will be required to access them,
depending on the configuration of the remote SSH server.

The same data cache directory specified with `-d` can be used for different
hosts at the same time. Each host will be stored and looked up in a
subdirectory based on its hostname.

To avoid having to specify the same parameters again and again there exists
also an environment variable `SQUINNIE_OPTS` that can be used like this:

```
$ export SQUINNIE_OPTS="--mode ssh --entry root@host -d /tmp/my_test_scan"
$ squinnie --filesystem
```

## Advanced Usage

Show which processes run with which capabilities:
```
$ squinnie -d /tmp/my_test_scan/ | grep CAP_
```

Show which files on the filesystem have which capabilities set (usually e.g. `/bin/ping`):
```
$ squinnie -d /tmp/my_test_scan/ --filesystem --capabilities
```

## SUSE OpenStack Cloud 7

To scan many nodes of a SUSE OpenStack Cloud instance interactively, use:
```
$ squinnie -d /tmp/my_test_scan/ -m susecloud -e <ip-of-cloud-admin-node>
```

By default, all nodes are scanned, but only the results of the admin node are shown. To show all, you can use:
```
$ squinnie -d /tmp/my_test_scan/ -m susecloud -e <ip-of-cloud-admin-node> -a
```

## Future Development

This software is not yet feature complete. More security sensitive contexts
can be identified, additional relevant data collected and especially a
graphical display of the collected data are on the whishlist.

## Name Change

This project was formerly known as "Hamster", but it turned out that a larger
open-source project under that name already exists. Therefore it was renamed
to Squinnie, one of the few rodent names not yet widely used in software
projects.

## Authors and Contact

This software is mainly developed by current and former employees of SUSE
Linux:

- Benjamin Deuter
- Jannik Main
- Matthias Gerstner <matthias.gerstner@suse.com> (current maintainer)
- Sebastian Kaim

For questions please reach out to the current maintainer. Contributions and
bug reports should go through the Github issue tracker / pull request
interface.

For the purpose of secure communication (e.g. privately reporting a security
issue) please contact the maintainer via GPG encrypted mail:

- <matthias.gerstner@suse.com>:
    * GPG Key-ID: 0x14C405C971923553
    * Fingerprint `3559 3A99 9BF6 D633 F287 1370 BD61 7A00 1534 7DC0`
