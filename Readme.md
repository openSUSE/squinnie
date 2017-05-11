# Cloud Scanner

This is a simple test suite for automating the analysis of the SUSE OpenStack Cloud 7. This code has been produced by Benjamin Deuter during an internship at the SUSE Linux GmbH.

## Installation

The requirements for this project can be found in `requirements.txt`.

## Usage

`./cloud_scanner.py` is a global wrapper that makes use of almost all other Python files at some point.

```
$ mkdir -p /tmp/myproject/
$ ./cloud_scanner.py -d /tmp/data -e <crowbar-admin-node>
```
For a start, this scans the admin node and acquires its crowbar configuration. Then it scans the admin node itself plus all nodes crowbar knows about. It will print a general overview of the admin node, use `-a/-all` to print a report of all nodes at once (though this might be rather long). Use `--help` to learn about more filter options.

```
$ mkdir -p /tmp/myproject/
$ ./dump_crowbar_network.py -o /tmp/myproject/network.json -e <crowbar-admin-node>
$ ./dump_node_data.py -i /tmp/myproject/network.json -o /tmp/myproject/
$ ./view_node_data.py -i /tmp/myproject/<some-node>.p
```
This is the above command broken down into its sub-tools.
