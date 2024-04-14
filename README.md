This repository contains source code for custom implementations of some basic networking utilities.

Upon completion and submisison, this will fulfill the honors option requirement for CMPEN 331 (Computer Networks).

## Instructions for use
First, clone this repository to your machine.
### Compilation
From the top-level directory of this repository, run `make`.

### Ping
This utility may require `sudo` privileges to run since it uses 'raw' sockets.

Usage: `ping362 <target>`
* `<target>` can be either an IP address or a hostname. Currently, only IPv4 addresses are supported.

### Traceroute
This utility may require `sudo` privileges to run since it uses 'raw' sockets.

Usage: `traceroute362 <target>`
* `<target>` can be either an IP address or a hostname. Currently, only IPv4 addresses are supported.
