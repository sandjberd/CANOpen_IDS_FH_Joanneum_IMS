#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "config.h"
#include "wifi_mqtt.h"
#include "can_monitor.h"
#include "ids_engine.h"

static const char *TAG = "BLUE_TEAM";

void app_main(void)
{
    ESP_LOGI(TAG, "================================");
    ESP_LOGI(TAG, " BLUE TEAM NODE -- CANopen IDS");
    ESP_LOGI(TAG, "================================");

    ids_init();
    ids_set_mode(IDS_MODE_B);
    ids_whitelist_add(0x01);

    ESP_ERROR_CHECK(can_monitor_init());
    can_monitor_start();

    if (wifi_init_sta() == ESP_OK) {
        ESP_ERROR_CHECK(mqtt_start());
    } else {
        ESP_LOGE(TAG, "WiFi failed -- IDS running in local-log mode");
    }

    ESP_LOGI(TAG, "Blue team node operational");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
