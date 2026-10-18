#include "esp_wifi_types_generic.h"
#include "freertos/FreeRTOS.h"
#include "freertos/projdefs.h"
#include "freertos/task.h"
#include "nvs.h"
#include <stdbool.h>
#include <stdio.h>

#include <nvs_flash.h>

#include <esp_err.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_event.h>
#include <esp_wifi.h>

static const char *TAG = "main";
static volatile uint32_t s_packet_count = 0;

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

void init_netif(void) {
    ESP_ERROR_CHECK(esp_netif_init());
}

void init_event_loop(void) {
    ESP_ERROR_CHECK(esp_event_loop_create_default());
}

static void sniffer_packet_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    s_packet_count++;
}

void init_wifi(void) {

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_packet_handler);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
    };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_wifi_set_promiscuous(true);

}

void app_main (void) {
    init_nvs();
    init_netif();
    init_event_loop();
    init_wifi();

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        printf("%lu\n", s_packet_count);
    }
}
