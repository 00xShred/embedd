#include "esp_wifi_types_generic.h"
#include "esp_wifi_types_native.h"
#include "freertos/FreeRTOS.h"
#include "freertos/projdefs.h"
#include "freertos/task.h"
#include "nvs.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <nvs_flash.h>

#include <esp_err.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_event.h>
#include <esp_wifi.h>
#include <sys/types.h>

static const char *TAG = "main";
static volatile uint32_t s_packet_count = 0;

// Packet counters struct.
// Why 'volatile'? The Wi-Fi callback updates these in the background,
// while app_main reads them. 'volatile' tells the compiler:
// "Don't cache this in a CPU register. Always read fresh from RAM."
typedef struct {
    volatile uint32_t total;
    volatile uint32_t mgmt;
    volatile uint32_t ctrl;
    volatile uint32_t data;
    volatile uint32_t deauth;
} wifi_stats_t;

static wifi_stats_t s_stats = {0};

// NVS = Non-Volatile Storage (flash memory).
// We don't save sniffed packets to flash (that would kill the chip).
// But Espressif's Wi-Fi driver refuses to start without NVS because it stores
// factory radio tuning / RF calibration data here.
// If the partition is full or corrupted, wipe it and re-init.
void init_nvs(void) {
    esp_err_t ret = nvs_flash_init();

    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition needs erase (err %s), erasing...", esp_err_to_name(ret));
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }

    ESP_ERROR_CHECK(ret);
    ESP_LOGI(TAG, "NVS initialized successfully.");
}

// Initialize TCP/IP network adapter stack (LwIP).
// Even though sniffer doesn't use IP/TCP, ESP-IDF Wi-Fi driver internals require it.
void init_netif(void) {
    ESP_ERROR_CHECK(esp_netif_init());
}

// System event loop (pub/sub message bus).
// Lets background drivers broadcast events (e.g. "Wi-Fi started") without busy-waiting.
void init_event_loop(void) {
    ESP_ERROR_CHECK(esp_event_loop_create_default());
}

// Callback invoked by Wi-Fi driver task whenever radio catches a frame.
// WARNING: Runs in high-priority driver context. Keep it fast. No heavy blocking/printf here.
static void sniffer_packet_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;

    // Standard 802.11 MAC header is minimum 24 bytes:
    // Frame Control (2B) + Duration (2B) + 3x MAC addrs (18B) + SeqCtrl (2B).
    // Drop anything shorter to prevent buffer over-read.
    if (p->rx_ctrl.sig_len < 24) {
        return;
    }

    // Byte 0 contains: [Bits 7..4: Subtype] [Bits 3..2: Type] [Bits 1..0: Version]
    // 1. Shift right by 2 to align Type to bit 0. Mask with 0x03 (0b00000011) to isolate 2 bits.
    //    Type 0 = Management, 1 = Control, 2 = Data.
    uint8_t frame_type = (p->payload[0] >> 2) & 0x03;

    // 2. Shift right by 4 to align Subtype. Mask with 0x0F (0b00001111) to isolate 4 bits.
    uint8_t subtype = (p->payload[0] >> 4) & 0x0F;

    s_stats.total++;

    switch (frame_type) {
        case 0: // Management frame
            s_stats.mgmt++;
            // Subtype 0x0C (12 decimal) = Deauthentication frame.
            // Often spoofed by attackers to force clients to reconnect so they can grab WPA2 handshakes.
            if (subtype == 0x0C) {
                s_stats.deauth++;
            }
            break;
        case 1: // Control frame (ACK, RTS, CTS)
            s_stats.ctrl++;
            break;
        case 2: // Data frame (encrypted user traffic)
            s_stats.data++;
            break;
        default:
            break;
    }

    s_packet_count++;
}

void init_wifi(void) {
    // Load default Wi-Fi task priorities, buffers, and queue sizes
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    // CRITICAL: Keep Wi-Fi settings in RAM only, NOT flash.
    // Default is FLASH. When we channel-hop (switching channels rapidly),
    // saving to flash would wear out and destroy the flash chip silicon.
    esp_wifi_set_storage(WIFI_STORAGE_RAM);

    // MODE_NULL = Ghost mode.
    // Powers on radio receiver, but no client (STA) and no router (AP) logic.
    // No connection, no IP, just raw RF listening.
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();

    // Lock tuner to 2.4GHz Channel 1 (2412 MHz) for now
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

    // Give driver our function pointer: "when packet hits antenna, call this"
    esp_wifi_set_promiscuous_rx_cb(&sniffer_packet_handler);

    // Pass all 3 packet families (Management, Control, Data) to our callback
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
    };
    esp_wifi_set_promiscuous_filter(&filter);

    // Master switch: disable hardware MAC filter, receive EVERYTHING
    esp_wifi_set_promiscuous(true);
}

// app_main is spawned by FreeRTOS as an initial task.
void app_main (void) {
    init_nvs();
    init_netif();
    init_event_loop();
    init_wifi();

    // Dashboard loop: prints stats once per second.
    // vTaskDelay yields CPU to FreeRTOS scheduler so other tasks (Wi-Fi driver) can run.
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        printf("[CH 1] Total: %lu | Mgmt: %lu (Deauth: %lu) | Data: %lu | Ctrl: %lu\n",
               s_stats.total, s_stats.mgmt, s_stats.deauth, s_stats.data, s_stats.ctrl);
    }
}
