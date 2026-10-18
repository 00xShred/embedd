# ESP32-C3-802.11-sniffer

Promiscuous mode Wi-Fi packet counter for ESP32-C3 using ESP-IDF.

Sniffs 802.11 packets on channel 1 with all frame filters enabled and logs total packet counts every second over USB-Serial/JTAG.

## Build & Flash

```bash
idf.py set-target esp32c3
idf.py build
idf.py -p <PORT> flash monitor
```
