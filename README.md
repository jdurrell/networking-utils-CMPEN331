This repository contains source code for custom implementations of some basic networking utilities. These have been tested on Ubuntu 20.04.

Upon completion and submisison, this will fulfill the honors option requirement for CMPEN 331 (Computer Networks).

## Instructions for use
First, clone this repository to your machine.
### Compilation
From the top-level directory of this repository, run `make`.

### Ping
This utility requires `sudo` privileges to run since it uses 'raw' sockets. Alternatively, you can grant the executable the proper capability by running the command `sudo setcap cap_net_raw+ep ./ping362`.

Usage: `sudo ./ping362 <target> -[(4|6])`
* `<target>` can be either an IP address or a hostname.
* The flags `-4` or `-6` can be added to force using either IPv4 or IPv6. If neither flag is provided, IPv4 is used by default.

### Traceroute
This utility requires `sudo` privileges to run since it uses 'raw' sockets. Alternatively, you can grant the executable the proper capability by running the command `sudo setcap cap_net_raw+ep ./traceroute362`.

Usage: `sudo ./traceroute362 <target>`
* `<target>` can be either an IP address or a hostname. Currently, only IPv4 addresses are supported.

## Uninstallation
To uninstall, simply delete the top-level folder of this repository from your machine.