# Cloud Scanner

This is a simple test suite for automating the analysis of the SUSE OpenStack Cloud 7. This code has been produced by Benjamin Deuter during an internship at the SUSE Linux GmbH.

## Installation

The requirements for this project can be found in `requirements.txt`.

## Usage

```
$ ./update_cap_data.py -o cap_data.json
$ ./dump_crowbar_network.py -e <crowbar-entry-node> -o network.json
$ mkdir data
$ ./dump_node_data.py -i network.json -o data/
$ ./view_node_data.py -i data/<some-node>.yml
```
