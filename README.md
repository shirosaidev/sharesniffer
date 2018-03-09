# sharesniffer
Network share sniffer and auto-mounter for crawling remote file systems

## How to use

Example to find all hosts in 192.168.56.0/24 network and auto-mount at /mnt:

```sh
python sniffshares.py -l 4 --hosts 192.168.56.0/24 -a -m /mnt
```

### CLI Options

```
usage: sniffshares.py [-h] [--hosts HOSTS] [-e EXCLUDEHOSTS] [-l SPEEDLEVEL]
                      [-n] [--nfsmntopt NFSMNTOPT] [-s]
                      [--smbmntopt SMBMNTOPT] [--smbtype SMBTYPE]
                      [--smbuser SMBUSER] [--smbpass SMBPASS] [-a]
                      [-m MOUNTPOINT] [-p MOUNTPREFIX] [-v] [--debug] [-q]
                      [-V]

optional arguments:
  -h, --help            show this help message and exit
  --hosts HOSTS         Hosts to scan, example: 10.10.56.0/22 or 10.10.56.2
                        (default: scan all hosts)
  -e EXCLUDEHOSTS, --excludehosts EXCLUDEHOSTS
                        Hosts to exclude from scan, example:
                        10.10.56.1,10.10.56.254
  -l SPEEDLEVEL, --speedlevel SPEEDLEVEL
                        Scan speed aggressiveness level from 3-5, lower for
                        more accuracy (default: 4)
  -n, --nfs             Scan network for nfs shares
  --nfsmntopt NFSMNTOPT
                        nfs mount options (default: ro,nosuid,nodev,noexec,udp
                        ,proto=udp,noatime,nodiratime,rsize=1024,dsize=1024,ve
                        rs=3,rdirplus)
  -s, --smb             Scan network for smb shares
  --smbmntopt SMBMNTOPT
                        smb mount options (default: ro,nosuid,nodev,noexec,udp
                        ,proto=udp,noatime,nodiratime,rsize=1024,dsize=1024)
  --smbtype SMBTYPE     Can be smbfs (default) or cifs
  --smbuser SMBUSER     smb username (default: guest)
  --smbpass SMBPASS     smb password (default: none)
  -a, --automount       Auto-mount any open nfs/smb shares
  -m MOUNTPOINT, --mountpoint MOUNTPOINT
                        Mountpoint to mount shares (default: ./)
  -p MOUNTPREFIX, --mountprefix MOUNTPREFIX
                        Prefix for mountpoint directory name (default:
                        sharesniffer)
  -v, --verbose         Increase output verbosity
  --debug               Debug message output
  -q, --quiet           Run quiet and just print out any possible mount points
                        for crawling
  -V, --version         Prints version and exits
  ```
