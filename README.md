# chitose

An iftop alternative for cumulated network traffic monitoring, for OSS mirror admins.

**Outbound traffic only currently**.

## Build

```bash
go build
```

This uses gopacket and thus NOT supporting `CGO_ENABLED=0` for static linking.

## Usage

```console
> ./chitose -h
Usage of ./chitose:
  -i string
        Interface to listen on (default "eth0")
```

You might need root privilege to run this program.

## Naming

Same as the nginx log analyzer [ayano](https://github.com/taoky/ayano),
and chitose shares some code with that :)
