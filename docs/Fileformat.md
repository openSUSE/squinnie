# Format of the data dump

Most of the data is simple pickled and gzipped. To inspect the contents of a `.p.gz` file one can the use `dumphelper.py` script.

## Directories

The data is saved in the directory given via `-d`, which will contain a subdirectory for each hostname. In this subdirectory are several `.p.gz` files as well as `filesystem.db`.

## The different files

### children.p.gz

This file contains the children for each existing process in the format `pid: [ childpid, childpid, ... ]`.

### networking.p.gz

This file contains information on active and listening sockets for each network and socket protocol (tcp, udp for IPv4 and IPv6 as well as unix sockets).

TODO: Describe the format of the table.

### parents.p.gz

This file contains the parent pid for each process in the format `pid: parent`.

### proc_data.p.gz

The data for each process in the format `pid: { data, ... }`. Example data for a process:

```
  22849: { 'CapAmb': 0,
           'CapBnd': 274877906943,
           'CapEff': 274877906943,
           'CapInh': 0,
           'CapPrm': 274877906943,
           'Gid': (0, 0, 0, 0),
           'Groups': [],
           'Seccomp': False,
           'Uid': (0, 0, 0, 0),
           'executable': '/sbin/dhclient',
           'open_files': { '0': {...},
                           '1': {...},
                           '2': {...},
                           '20': {...},
                           '21': {...},
                           '3': {...},
                           '4': {...},
                           '5': {...},
                           '6': {...}},
           'parameters': '-d -q -sf /usr/lib/nm-dhcp-helper -pf /var/run/dhclient-eth0.pid -lf /var/lib/NetworkManager/dhclient-12345-eth0.lease -cf /var/lib/NetworkManager/dhclient-eth0.c' }
```

### userdata.p.gz

This file contains the names for each user and group matched to uid/gid. It looks like this:

```
{ 'gids': { 0: 'root',
            1: 'bin',
            2: 'daemon',
            3: 'sys',
            ....
            1000: 'network',
            65533: 'nobody',
            65534: 'nogroup'},
  'uids': { 0: 'root',
            1: 'bin',
            ...
            65534: 'nobody'}}

```

### filesystem.db

This is an sqlite3 database for storing the filesystem. It has a single table called `inodes` which contains all files and directories. It has the following columns:

- `id`: The primary key, replacing `rowid`.
- `parent`: The id of the directory the file/directory/... is contained in.
- `uid` and `gid`: Owner userid and groupid.
- `caps`: The capabilities as reported by stat.
- `mode`: The file mode as reported by stat (i.e. sticky bit, suid bit, ...).
- `type`: A single char describing the type of the entry. The chars are as defined in `man 1p ls` and are generated via `getTypeChar(mode)` in `sscanner/file_mode.py`.
- `name`: The filename.
- `path`: The path to the file with leading slash and without filename or trailing slash. This can in theory be reconstructed by recursively querying the parents, but having this field makes the queries a lot easier.


