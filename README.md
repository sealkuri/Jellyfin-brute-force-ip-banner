# Jellyfin-brute-force-ip-banner
## About

A small Python script used to watch Jellyfin logs for a brute force login attack and automatically blocks IP.

## How this works

1. Follows 'jellyfin.service' journal in realtime
2. Detects failed logins and gets the ip
3. Counts failures per IP within a set time window
4. When reached set maximum attempts:
    - blocks with 'iptables' DROP rule,
    - records ip and time in an SQlite database,
    - notifies about ban with optional ntfy notifications
  
## Features

- Configurable time window and attempt limit
- IP whitelist
- Ban history in SQLite
- Optional notifications via ntfy

## Prerequisites

- Jellyfin running on linux as a systemd service
- Using iptables as firewall
- Correctly configured [Jellyfin Known Proxies](https://jellyfin.org/docs/general/post-install/networking/reverse-proxy/#forwarded-for-headers) if applicable
- Python 3.8+
- Python packages: 'requests', 'python-systemd'

### Optional

If using ssh, give ssh user ability only run iptables commands.


## Usage

```bash
sudo python3 Jellyfin-log-parser.py
```

## Configuration

On first run, 'config.ini' is created next to script:

```ini
[SETTINGS]
; in minutes
Time window = 5       
Max attempts = 5

[SSH]
Enabled = no
User =
Server =

[Whitelist]
; one IP per line
Allowed IPs =         

[NTFY]
Enabled = no
Server = https://ntfy.sh
Topic name = 
```


## Todo
- [ ] Finish readme
- [ ] Add docker and other os compatability?
