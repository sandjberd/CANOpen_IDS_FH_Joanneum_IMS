#include "wifi_mqtt.h"
#include "config.h"

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "mqtt_client.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "WIFI_MQTT";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static EventGroupHandle_t wifi_event_group;
static int s_retry = 0;
static esp_mqtt_client_handle_t mqtt_client = NULL;
static bool mqtt_connected = false;

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry < WIFI_MAX_RETRY) {
            esp_wifi_connect();
            s_retry++;
        } else {
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&e->ip_info.ip));
        s_retry = 0;
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

esp_err_t wifi_init_sta(void)
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

    wifi_config_t wcfg = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASSWORD,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wcfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to SOC WiFi '%s'...", WIFI_SSID);
    EventBits_t bits = xEventGroupWaitBits(
        wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(30000));

    return (bits & WIFI_CONNECTED_BIT) ? ESP_OK : ESP_FAIL;
}

static void mqtt_event_handler(void *args, esp_event_base_t base,
                               int32_t id, void *event_data)
{
    switch ((esp_mqtt_event_id_t)id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected to host");
        mqtt_connected = true;
        esp_mqtt_client_publish(mqtt_client, MQTT_HEARTBEAT_TOPIC,
                                "blue_online", 0, 1, 1);
        break;
    case MQTT_EVENT_DISCONNECTED:
        mqtt_connected = false;
        ESP_LOGW(TAG, "MQTT disconnected");
        break;
    default:
        break;
    }
}

esp_err_t mqtt_start(void)
{
    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = MQTT_BROKER_URI,
        .session.last_will.topic = MQTT_HEARTBEAT_TOPIC,
        .session.last_will.msg = "blue_offline",
        .session.last_will.qos = 1,
        .session.last_will.retain = 1,
    };
    mqtt_client = esp_mqtt_client_init(&cfg);
    if (!mqtt_client) return ESP_FAIL;
    esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID,
                                   mqtt_event_handler, NULL);
    return esp_mqtt_client_start(mqtt_client);
}

static const char *severity_str(alert_severity_t s)
{
    switch (s) {
    case ALERT_INFO:     return "info";
    case ALERT_WARNING:  return "warning";
    case ALERT_CRITICAL: return "critical";
    default:             return "unknown";
    }
}

void mqtt_publish_alert(const ids_alert_t *alert)
{
    ESP_LOGW(TAG, "[ALERT][%s] %s: %s",
             severity_str(alert->severity), alert->rule, alert->description);

    if (!mqtt_connected) return;

    char payload[384];
    int n = snprintf(payload, sizeof(payload),
        "{"
        "\"ts_us\":%llu,"
        "\"severity\":\"%s\","
        "\"rule\":\"%s\","
        "\"suspect_node\":\"0x%02X\","
        "\"suspect_cob\":\"0x%03X\","
        "\"description\":\"%s\""
        "}",
        (unsigned long long)alert->timestamp_us,
        severity_str(alert->severity),
        alert->rule,
        alert->suspect_node_id,
        alert->suspect_cob_id,
        alert->description);

    if (n > 0) {
        esp_mqtt_client_publish(mqtt_client, MQTT_ALERT_TOPIC,
                                payload, 0, 1, 0);
    }
}
