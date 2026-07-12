#include "can_monitor.h"
#include "config.h"
#include "ids_engine.h"
#include "wifi_mqtt.h"

#include "driver/twai.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "CAN_MON";

esp_err_t can_monitor_init(void)
{
    twai_general_config_t g_config = TWAI_GENERAL_CONFIG_DEFAULT(
        CAN_TX_GPIO, CAN_RX_GPIO, TWAI_MODE_LISTEN_ONLY);
    g_config.rx_queue_len = 64;

    twai_timing_config_t t_config = TWAI_TIMING_CONFIG_500KBITS();
    twai_filter_config_t f_config = TWAI_FILTER_CONFIG_ACCEPT_ALL();

    esp_err_t err = twai_driver_install(&g_config, &t_config, &f_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "TWAI install failed: %s", esp_err_to_name(err));
        return err;
    }
    err = twai_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "TWAI start failed: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "TWAI sniffer running (listen-only) at %d kbps",
             CAN_BITRATE_KBPS);
    return ESP_OK;
}

static void emit(const ids_alert_t *a) { mqtt_publish_alert(a); }

static void process_frame(const twai_message_t *msg)
{
    uint32_t cob_id = msg->identifier;
    uint64_t ts = esp_timer_get_time();
    ids_alert_t alert;

    can_frame_t f = {
        .cob_id = cob_id,
        .dlc = msg->data_length_code,
        .timestamp_us = ts,
    };
    memcpy(f.data, msg->data, 8);

    if (ids_check_busload(&f, &alert)) emit(&alert);

    if (cob_id == NMT_COB) {
        if (ids_check_nmt(&f, &alert)) emit(&alert);
        return;
    }

    if (cob_id >= 0x081 && cob_id <= 0x0FF) {
        uint8_t node_id = cob_id - EMCY_BASE;
        if (msg->data_length_code < 3) {
            ESP_LOGW(TAG, "Malformed EMCY (DLC=%d) from 0x%03lX",
                     msg->data_length_code, (unsigned long)cob_id);
            return;
        }
        emcy_event_t evt = {
            .node_id = node_id,
            .error_code = (uint16_t)msg->data[0] | ((uint16_t)msg->data[1] << 8),
            .error_register = msg->data[2],
            .timestamp_us = ts,
        };
        memcpy(evt.raw_data, msg->data, 8);
        ESP_LOGI(TAG, "EMCY rx: node=0x%02X code=0x%04X reg=0x%02X",
                 node_id, evt.error_code, evt.error_register);
        if (ids_check_emcy(&evt, &alert)) emit(&alert);
        return;
    }

    if ((cob_id >= 0x181 && cob_id <= 0x1FF) ||
        (cob_id >= 0x281 && cob_id <= 0x2FF)) {
        if (ids_check_pdo(&f, &alert)) emit(&alert);
        return;
    }

    if ((cob_id >= 0x581 && cob_id <= 0x5FF) ||
        (cob_id >= 0x601 && cob_id <= 0x67F)) {
        if (ids_check_sdo(&f, &alert)) emit(&alert);
        return;
    }

    if (cob_id >= 0x701 && cob_id <= 0x77F) {
        uint8_t node_id = cob_id - HEARTBEAT_BASE;
        uint8_t state = (msg->data_length_code >= 1) ? msg->data[0] : 0xFF;
        if (ids_check_heartbeat(node_id, state, ts, &alert)) emit(&alert);
        return;
    }

    if (cob_id == LSS_MASTER_COB || cob_id == LSS_SLAVE_COB) {
        if (ids_check_lss(&f, &alert)) emit(&alert);
        return;
    }
}

static void rx_task(void *arg)
{
    twai_message_t msg;
    while (1) {
        if (twai_receive(&msg, pdMS_TO_TICKS(1000)) == ESP_OK) {
            process_frame(&msg);
        }
        static uint64_t last_periodic = 0;
        uint64_t now = esp_timer_get_time();
        if (now - last_periodic > 500000) {
            ids_alert_t alerts[MAX_LEGIT_NODES];
            int n = ids_periodic_check(alerts, MAX_LEGIT_NODES);
            for (int i = 0; i < n; i++) {
                mqtt_publish_alert(&alerts[i]);
            }
            last_periodic = now;
        }
    }
}

void can_monitor_start(void)
{
    xTaskCreate(rx_task, "can_rx", 6144, NULL, 10, NULL);
    ESP_LOGI(TAG, "CAN monitor task started");
}
