# MakerMate WiFi for Elegoo Neptune 4

You can try it here: https://www.makermate.org/wifi-neptune

Automatically install persistent Wi‑Fi on Neptune 4 printers with a single USB swap (install stick → Wi‑Fi dongle).

## Quick start (use the prebuilt USB)
1) Grab the ready-made `ELEGOO_UPDATE_DIR` folder in `output/` (or the latest release asset) and copy it to the root of a FAT32 USB drive without renaming it.  
2) Edit `ELEGOO_UPDATE_DIR/wifi_credentials.txt`:
   ```
   SSID=YourWiFiNetworkName
   PASSWORD=YourWiFiPassword
COUNTRY=US
   HOSTNAME=makermate   # optional, becomes HOSTNAME.local
   ```
3) Eject the USB, plug it into the printer, and power-cycle. Wait ~2–3 minutes for auto-install.  
4) Remove the USB, insert your Wi‑Fi dongle, and wait ~1–2 minutes for the link to come up.  
5) Find the printer’s IP from your router; optional SSH: `ssh mks@<ip>` (password `makerbase`).

**Single USB port note:** Neptune 4 has one USB port—swap the install stick for the Wi‑Fi dongle (or use a tiny hub if you want both inserted).

## Compatibility & requirements
- Printers: Neptune 4 / 4 Pro tested; 4 Plus / 4 Max expected to work (MKS Linux).
- Wi‑Fi dongles: RTL8188CUS/EUS/8192CU work best (e.g., TP-Link TL‑WN725N, Edimax EW‑7811Un).
- Needs a FAT32 USB stick and a 2.4 GHz network; set `COUNTRY` for channel compliance.

## What gets installed
- `/usr/local/bin/wifi-watchdog.sh` + systemd service `makermate-wifi` to manage `wpa_supplicant` + `dhclient`.
- `/etc/wpa_supplicant/wpa_supplicant-wlan0.conf` generated from your `wifi_credentials.txt`.
- Logs at `/var/log/makermate-wifi.log`; helper script `wifi-status.sh`. mDNS packages auto-install when the printer has internet; hostname defaults to `makermate.local` (override via `HOSTNAME=`).

## Quick troubleshooting
- No Wi‑Fi? Confirm the dongle is RTL8188/8192 and recognized (`wlan0` present).  
- Need details? `tail -f /var/log/makermate-wifi.log` or `wifi-status.sh`.  
- Service restarts until it connects; first boot may take an extra minute while mDNS packages install.

## Uninstall
SSH in and run `sudo apt remove makermate-wifi` (cleans service and files).

## Build it yourself (optional)
On a Linux machine with a FAT32 USB inserted:
```
sudo chmod +x generate_usb_setup.sh
sudo ./generate_usb_setup.sh
```

## License
MIT — see `LICENSE`.

## Disclaimer
Use at your own risk. Not affiliated with or endorsed by Elegoo. Firmware modifications may void warranties. Always keep backups.
