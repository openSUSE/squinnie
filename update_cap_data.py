#!/usr/bin/env python2

# Standard library modules
from __future__ import print_function
from __future__ import with_statement
import codecs
import re
import json
from collections import OrderedDict

file_name = "/usr/include/linux/capability.h"

with codecs.open(file_name, "r", encoding="utf-8") as fi:
    file_data = fi.read()

assert file_data

regex = re.compile("#define (CAP_[A-Z_]+)\s+(\d+)", re.MULTILINE)

cap_data = OrderedDict()
for m in re.finditer(regex, file_data):
    cap_int  = int(m.group(2))
    cap_name = str(m.group(1))
    cap_data[cap_name] = cap_int

    # print("%s : %s" % (cap_int, cap_name))

file_name = "data/cap_data.json"
with codecs.open(file_name, "w", encoding="utf-8") as fi:
    json.dump(cap_data, fi, indent=4, sort_keys=True)
