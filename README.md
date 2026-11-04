# Jellyfin-brute-force-ip-banner
## About
A personal script I use to automatically parse and ban ip's that seem to be brute force attacking.
Keeps record of banned ip's using sqlite3 and sends notifications about banned ip's with ntfy

## Getting Started 
### Prerequisites
- Jellyfin running on linux as a systemd service
- Using iptables as firewall
- Correctly configured [Jellyfin Known Proxies](https://jellyfin.org/docs/general/post-install/networking/reverse-proxy/#forwarded-for-headers) if applicable

Python modules
  - systemd-python
  - requests

## Usage

## Todo
- [ ] Finish readme
- [ ] Add docker and other os compatability?
