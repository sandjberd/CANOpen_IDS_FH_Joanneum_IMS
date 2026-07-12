#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "canopen_victim.h"
#include "config.h"

static const char *TAG = "MAIN";

void app_main(void)
{
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, " VICTIM NODE - CANopen Node 0x%02X", NODE_ID);
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "Object Dictionary:");
    ESP_LOGI(TAG, "  0x1017:00  Heartbeat time    = %d ms  (read-only)",
             HEARTBEAT_PERIOD_MS);
    ESP_LOGI(TAG, "  0x6000:00  Sensor value      = 0x1234 (read/write)");
    ESP_LOGI(TAG, "  0x6001:00  Setpoint          = 0x0064 (read/write)");
    ESP_LOGI(TAG, "PDO schedule:");
    ESP_LOGI(TAG, "  TPDO1 (0x181)  every %d ms - sensor, tick, adc, flags",
             PDO1_PERIOD_MS);
    ESP_LOGI(TAG, "  TPDO2 (0x281)  every %d ms - setpoint, uptime, state",
             PDO2_PERIOD_MS);

    ESP_ERROR_CHECK(canopen_victim_init());
    canopen_victim_start();

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        ESP_LOGI(TAG, "Alive - NMT state: 0x%02X",
                 (uint8_t)canopen_get_nmt_state());
    }
}
