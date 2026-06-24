# Zuicity Install

A one-click install and management script for [zuicity](https://github.com/teracoot/zuicity).

## Install

```bash
wget -N --no-check-certificate https://raw.githubusercontent.com/teracoot/zuicity-install/main/zuicity.sh && bash zuicity.sh
```

## Features

- Install / uninstall / update zuicity (`zuicity-server`) with a single menu.
- Certificate options: self-signed (bing.com), acme.sh automatic, or your own.
- Random or custom port and password; UUID is generated automatically.
- At the port/password prompts, press Enter to use generated random values.
- ACME mode verifies the domain through the server resolver, uses an existing
  nginx ACME webroot when available, falls back to standalone mode only when
  port `80` is free, installs certificates to `/root/cert.crt` and
  `/root/private.key`, schedules daily `acme.sh --cron` renewal, and stores a
  reload command so `zuicity-server` restarts after renewed certificates are
  installed.
- Generates the server config (`/etc/zuicity/server.json`), a client config
  (`/root/zuicity/client.json`), and a Go-compatible share link
  (`/root/zuicity/url.txt`).
- Start / stop / restart and live config editing (port / UUID / password).

## Paths

| Item | Path |
|---|---|
| Server binary | `/usr/bin/zuicity-server` |
| Client binary | `/usr/bin/zuicity-client` |
| Server config | `/etc/zuicity/server.json` |
| systemd unit | `/etc/systemd/system/zuicity-server.service` |
| Client config & share link | `/root/zuicity/` |

## Supported systems

Debian / Ubuntu / CentOS / RHEL / Fedora on `x86_64`.

## License

GPL-3.0.
