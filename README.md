# `ruuf` - A simple yet convenient cross-platform ARP spoofer

Poison the ARP cache of the given victim, thereby redirecting the traffic to the target therefrom
through the local machine.

## Installing `ruuf`

You may choose from either option:

1. Download the latest binary (for Linux) from the
   [Releases](https://github.com/No3cho/ruuf/releases) page.
2. Build from source (mandatory for those on Windows or MacOS) via 
   `git clone https://github.com/No3cho/ruuf.git && cd ruuf && cargo build --release`.

## Using `ruuf`

```
USAGE:
    ruuf [FLAGS] [OPTIONS] -t <target-ip-addr> -v <victim-ip-addr>

FLAGS:
    -h, --help       Prints help information
    -d               Despoof upon receiving SIGINT (CTRL+C), SIGTERM or SIGHUP
    -V, --version    Prints version information

OPTIONS:
    -i <iface>                  Network interface to use
    -u <resolve-timeout>        ARP resolution timeout, in milliseconds
    -j <spoof-interval>         ARP spoofing interval, in milliseconds [default: 10000]
    -t <target-ip-addr>         Spoof as the machine with this IPv4 address
    -v <victim-ip-addr>         Poison the ARP Cache of the machine with this IPv4 address
```

## Notice

[`pnet`](https://crates.io/crates/pnet) is used by `ruuf` for networking. If you are using Windows,
please refer to the requirements listed by the [`pnet`](https://crates.io/crates/pnet) crate.

`ruuf` was developed and tested on Linux Mint 20.3.