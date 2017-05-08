# Cloud Scanner

This is a simple test suite for automating the analysis of the SUSE OpenStack Cloud 7. This code has been produced by Benjamin Deuter during an internship at the SUSE Linux GmbH.

## Installation

The requirements for this project can be found in `requirements.txt`.

## Usage

```
$ ./update_cap_data.py -o data/cap_data.json
$ ./dump_crowbar_network.py -e <crowbar-entry-node> -o data/network.json
$ ./dump_node_data.py -i data/network.json -o data/
$ ./view_node_data.py -i data/crowbar-c9-cloud-suse-de.yml
```
