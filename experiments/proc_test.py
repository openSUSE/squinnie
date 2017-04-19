#!/usr/bin/env python2
from collections import OrderedDict
import json

from proc import core
from proc.tree import get_process_tree

interesting_status_fields = [
    "PPid",
    "Gid",
    "Uid",
    "Groups",
    "Seccomp",
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
]

all_processes = list(core.find_processes())

all_data = OrderedDict()
for p in all_processes:
    key = p.pid
    value = OrderedDict()
    for f in interesting_status_fields:
        value[f] = p.status_fields[f]
    all_data[key] = value

with open("data_proc.json", "w") as fi:
    json.dump(all_data, fi, indent=4)
