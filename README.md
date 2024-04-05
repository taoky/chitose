# chitose

An iftop alternative for cumulated network traffic monitoring, for OSS mirror admins.

**Outbound traffic by default**.

## Build

```bash
go build
```

This uses gopacket and thus NOT supporting `CGO_ENABLED=0` for static linking.
You need to install libpcap to use this.

Note that binaries in Releases are compiled under Ubuntu 20.04 (glibc 2.31).

## Usage

```console
> ./chitose -h
Usage of ./chitose:
  -i string
        Interface to listen on (default "eth0")
  -inbound
        Show inbound traffic instead of outbound
  -no-netstat
        Do not detect active connections
```

You might need root privilege to run this program.

## Naming

Same as the nginx log analyzer [ayano](https://github.com/taoky/ayano),
and chitose shares some code with that :)

