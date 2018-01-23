# Format of the data dump

Most of the data is simple pickled and gzipped. To inspect the contents of a `.p.gz` file one can the use `dumphelper.py` script.

## Directories

The data is saved in the directory given via `-d`, which will contain a subdirectory for each hostname. In this subdirectory are several `.p.gz` files as well as `filesystem.db`.

## The different files

### children.p.gz

This file contains the children for each existing process in the format `pid: [ childpid, childpid, ... ]`.

### networking.p.gz

This file contains information on active and listening sockets for each network and socket protocol (tcp, udp for IPv4 and IPv6 as well as unix sockets). The file itself is a dict of protocols. 

The structure of the protocols is as following:

- *tcp*, *tcp6*, *udp* & *udp6*: `inode: [[local ip in hex, local port in hex], [remote ipor zero in hex, remote port or zero in hex`
- *netlink*: dict of `inode: type`, where type is the type of the socket as found in `/usr/include/linux/netlink.h`.
- *unix*: a dict of the format `inode: location`, where location is the location in the filesystem. The location might be prefixed with an `@` or empty if it's not a filesystem socket.
- *packet*: a dict in the format `inode: array of netlink attributes`. The attributes are ordered in the way they are found in `/proc/net/packet`. The headers are included in the file; they are _k, RefCnt, Type, Proto, Iface, R, Rmem, User, Inode_.

### parents.p.gz

This file contains the parent pid for each process in the format `pid: parent`.

### proc_data.p.gz

The data for each process in the format `pid: { data, ... }`. Example data for a process:

```
  22849: { 'CapAmb': 0,  # the capabilities the process has
           'CapBnd': 274877906943,
           'CapEff': 274877906943,
           'CapInh': 0,
           'CapPrm': 274877906943,
           'Gid': (0, 0, 0, 0),  # the process gids
           'Groups': [],
           'Seccomp': False,
           'Uid': (0, 0, 0, 0),  # the process uids
           'cmdline': '/usr/lib/systemd/systemd\x00--switched-root',  # the cmdline as found in /proc/$pid/cmdline
           'executable': '/sbin/dhclient',  # the name of the executable
           # the memory mappings as found in the /proc/$pid/maps file
           'maps': [ { 'address': '557b4df66000-557b4e0c8000',
                   'dev': '00:27',
                   'inode': '374429',
                   'offset': '00000000',
                   'pathname': '/usr/lib/systemd/systemd',
                   'perms': 'r-xp'},
                 { 'address': '557b4e2c8000-557b4e2ea000',
                   'dev': '00:27',
                   'inode': '374429',
                   'offset': '00162000',
                   'pathname': '/usr/lib/systemd/systemd',
                   'perms': 'r--p'}, ... ]
           'open_files': { '0': {...},
                           '1': {...},
                           '2': {...},
                           '20': {...},
                           '21': {...},
                           '3': {...},
                           '4': {...},
                           '5': {...},
                           '6': {...}},
           'parameters': '-d -q -sf /usr/lib/nm-dhcp-helper -pf /var/run/dhclient-eth0.pid -lf /var/lib/NetworkManager/dhclient-12345-eth0.lease -cf /var/lib/NetworkManager/dhclient-eth0.c',  # commandline parameters
           'parent': 0,  # pid of the parent process
           'pgroup': '1',(  # the process group
           'root': '/',  # the root (can be different if in chroot
           'session': '1',
           'starttime': '8',  # when the process started (ms since boot)
           # this is a dict of all threads the process has. The key is the thread id.
           # threads have a subset of the parameters a process has
           'threads': { '1': { 'CapAmb': 0,
                           'CapBnd': 274877906943,
                           'CapEff': 274877906943,
                           'CapInh': 0,
                           'CapPrm': 274877906943,
                           'Gid': (...),
                           'Groups': [],
                           'Seccomp': False,
                           'Uid': (...),
                           'cmdline': '/usr/lib/systemd/systemd\x00--switched-root\x00--system\x00--deserialize\x0024\x00',
                           'executable': '/usr/lib/systemd/systemd',
                           'parameters': '--switched-root --system --deserialize 24 '}}},
```

If the kernel is new enough, the umask will be included as well.

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


