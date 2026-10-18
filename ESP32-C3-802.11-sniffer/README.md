# ESP32-C3-802.11-sniffer

A Wi-Fi sniffer for the ESP32-C3, plain C with ESP-IDF and FreeRTOS. No Arduino.

Normally a Wi-Fi chip only hears packets addressed to it and the rest gets dropped in hardware. This project turns that filter off, so the ESP32 hears _everything_ on 2.4GHz: neighbors' routers, phones, smart TVs. It classifies what it hears, hops channels to cover the whole band, and blinks the onboard LED when it spots a deauthentication attack.

## What it does

- **Promiscuous mode** — hardware MAC filter off, every frame on the air lands in my callback
- **802.11 parsing** — shift and mask the Frame Control byte to get type (mgmt/ctrl/data) and subtype (beacon, deauth...)
- **Dashboard** — packet counters printed every second over USB
- **Channel hopper** — FreeRTOS task sweeps channels 1-13 every 100ms
- **Deauth IDS** — logs sender, victim, BSSID, reason code when a deauth shows up
- **LED alert** — onboard blue LED (GPIO8, active LOW) blinks on deauth

## Build & Flash

```bash
get_idf                      # one-time: source ESP-IDF
idf.py set-target esp32c3
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

Exit monitor: `Ctrl+]`. Flash won't connect? Hold `BOOT`, tap `RESET`, release `BOOT`, retry.

## How it fits together

```
[2.4GHz radio] → Wi-Fi driver → my callback (runs in driver's task)
    → drop noise/broken frames
    → parse 802.11 header (deauth?)
    → bump counters
         ↓
[app_main task]           [channel_hopper task]
  prints dashboard 1/sec    retunes radio every 100ms
  blinks LED on deauth
```

## Gotchas

- **printf went nowhere.** The Super Mini's USB port is the internal USB-Serial-JTAG, but ESP-IDF defaults console output to UART0. Fix: `CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y` in `sdkconfig.defaults`.
- **`printf("%u")` didn't build.** Here `uint32_t` is `unsigned long` and warnings are errors. Use `%lu` or `PRIu32`.
- **Never delay in the callback.** That's the watchdog reset above. Callback counts, `app_main` blinks.
- **I "detected" deauths that weren't there.** Corrupted RF noise randomly produces bytes that match subtype `0x0C` — fake deauths with garbage reason codes like 21067. Two filters fixed it: drop frames with `rx_ctrl.rx_state != 0` (checksum failed) and only parse frames the driver labels `WIFI_PKT_MGMT`.
- **`rx_ctrl.channel` always read 0** on the C3. My hopper task knows the channel it tuned to, so I keep my own `s_current_channel`.
- **Reason code printed giant numbers.** It's little-endian at bytes 24-25: `payload[24] | (payload[25] << 8)`. Real codes are small: 1, 2, 3, 7.
- **The Wi-Fi driver refuses to start without NVS flash**, even though I store nothing — its closed blob loads radio calibration from there. `init_nvs()` comes first, always.
- **`WIFI_STORAGE_RAM` or the board dies slowly.** Default Wi-Fi storage is flash; my hopper retunes 10x/sec, and that would wear out the flash chip in days.
- **pyenv fought the installer.** `export.sh` grabs whatever `python3` it finds; system Python 3.14 broke the venv detection. Fix: `PYENV_VERSION=3.12.14` in the `get_idf` alias.

## Output

```
[CH  3] Total: 196 | Mgmt: 170 (Deauth: 0) | Data: 26 | Ctrl: 0

[!] DEAUTH DETECTED [CH  3 | RSSI -83 dBm]
    Sender : 67:9d:35:64:ac:1e
    Victim : 4c:85:1f:e9:91:a7
    BSSID  : 54:2c:7b:50:a7:43
    Reason : 7
```

## Next

Features I want to tackle next:

- **Beacon/SSID logger** — parse TLV information elements to list networks by name #1
- **PCAP stream** — stream raw frames into Wireshark over USB (teaches FreeRTOS queues, producer/consumer) #3
- **Deauth transmit test** — second ESP32-C3 plays attacker against my own router, detector catches it end-to-end #2

## References

The docs in the order I needed them:

- [Build system](https://docs.espressif.com/projects/esp-idf/en/v5.3.2/esp32c3/api-guides/build-system.html) — how ESP-IDF projects are structured (the two CMakeLists, app_main, sdkconfig).
- [ESP-NETIF](https://docs.espressif.com/projects/esp-idf/en/v5.3.2/esp32c3/api-reference/network/esp_netif.html) — the TCP/IP plumbing the Wi-Fi driver insists on, even though I never use IP.
- [Event loop](https://docs.espressif.com/projects/esp-idf/en/v5.3.2/esp32c3/api-reference/system/esp_event.html) — the background message bus that lets drivers yell "hey, I started!" without busy-waiting.
- [Wi-Fi driver API](https://docs.espressif.com/projects/esp-idf/en/v5.3.2/esp32c3/api-reference/network/esp_wifi.html) — the main reference: Wi-Fi modes, and the [promiscuous mode section](https://docs.espressif.com/projects/esp-idf/en/v5.3.2/esp32c3/api-reference/network/esp_wifi.html#promiscuous-mode) with the callback, filters, and the packet struct I tear apart.
