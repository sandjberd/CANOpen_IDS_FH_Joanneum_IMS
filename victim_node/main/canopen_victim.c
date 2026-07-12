#include "canopen_victim.h"
#include "config.h"

#include "driver/twai.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "VICTIM";

typedef struct {
    uint16_t heartbeat_time_ms;
    uint16_t sensor_value;
    uint16_t setpoint;
} object_dictionary_t;

static object_dictionary_t od = {
    .heartbeat_time_ms = HEARTBEAT_PERIOD_MS,
    .sensor_value      = 0x1234,
    .setpoint          = 0x0064,
};

static nmt_state_t nmt_state = NMT_INITIALISING;
static SemaphoreHandle_t nmt_mutex = NULL;

static nmt_state_t get_nmt_state(void)
{
    nmt_state_t s;
    xSemaphoreTake(nmt_mutex, portMAX_DELAY);
    s = nmt_state;
    xSemaphoreGive(nmt_mutex);
    return s;
}

static void set_nmt_state(nmt_state_t s)
{
    xSemaphoreTake(nmt_mutex, portMAX_DELAY);
    nmt_state = s;
    xSemaphoreGive(nmt_mutex);
    ESP_LOGI(TAG, "NMT state -> 0x%02X", s);
}

static const char *nmt_state_name(nmt_state_t s)
{
    switch (s) {
    case NMT_INITIALISING:    return "INITIALISING";
    case NMT_PRE_OPERATIONAL: return "PRE-OPERATIONAL";
    case NMT_OPERATIONAL:     return "OPERATIONAL";
    case NMT_STOPPED:         return "STOPPED";
    default:                  return "UNKNOWN";
    }
}

static esp_err_t can_send(uint32_t cob_id, uint8_t dlc, const uint8_t *data)
{
    twai_message_t msg = {0};
    msg.identifier = cob_id;
    msg.data_length_code = dlc;
    msg.extd = 0;
    msg.rtr = 0;
    if (data && dlc) memcpy(msg.data, data, dlc);
    esp_err_t err = twai_transmit(&msg, pdMS_TO_TICKS(10));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "TX fail cob=0x%03lX: %s",
                 (unsigned long)cob_id, esp_err_to_name(err));
    }
    return err;
}

static void heartbeat_task(void *arg)
{
    ESP_LOGI(TAG, "Heartbeat task started (period=%d ms)", HEARTBEAT_PERIOD_MS);
    while (1) {
        nmt_state_t s = get_nmt_state();
        uint8_t payload = (uint8_t)s;
        can_send(COB_HEARTBEAT, 1, &payload);
        ESP_LOGD(TAG, "[HB] state=%s (0x%02X)", nmt_state_name(s), s);
        vTaskDelay(pdMS_TO_TICKS(HEARTBEAT_PERIOD_MS));
    }
}

static void tpdo1_task(void *arg)
{
    uint16_t tick = 0;
    uint16_t adc  = 0;
    ESP_LOGI(TAG, "TPDO1 task started (period=%d ms)", PDO1_PERIOD_MS);

    while (1) {
        if (get_nmt_state() == NMT_OPERATIONAL) {
            od.sensor_value = 100 + (tick % 900);
            adc = (adc + 13) % 1024;

            uint16_t flags = 0x0001;
            if (od.sensor_value > 800) flags |= 0x0002;

            uint8_t pdo[8];
            pdo[0] = od.sensor_value & 0xFF;
            pdo[1] = (od.sensor_value >> 8) & 0xFF;
            pdo[2] = tick & 0xFF;
            pdo[3] = (tick >> 8) & 0xFF;
            pdo[4] = adc & 0xFF;
            pdo[5] = (adc >> 8) & 0xFF;
            pdo[6] = flags & 0xFF;
            pdo[7] = (flags >> 8) & 0xFF;

            can_send(COB_TPDO1, 8, pdo);
            ESP_LOGD(TAG, "[TPDO1] sensor=%u tick=%u adc=%u flags=0x%04X",
                     od.sensor_value, tick, adc, flags);
            tick++;
        }
        vTaskDelay(pdMS_TO_TICKS(PDO1_PERIOD_MS));
    }
}

static void tpdo2_task(void *arg)
{
    uint32_t uptime = 0;
    ESP_LOGI(TAG, "TPDO2 task started (period=%d ms)", PDO2_PERIOD_MS);

    while (1) {
        if (get_nmt_state() == NMT_OPERATIONAL) {
            uint8_t pdo[8];
            pdo[0] = od.setpoint & 0xFF;
            pdo[1] = (od.setpoint >> 8) & 0xFF;
            pdo[2] = uptime & 0xFF;
            pdo[3] = (uptime >> 8) & 0xFF;
            pdo[4] = NODE_ID;
            pdo[5] = (uint8_t)get_nmt_state();
            pdo[6] = 0x00;
            pdo[7] = 0x00;

            can_send(COB_TPDO2, 8, pdo);
            ESP_LOGD(TAG, "[TPDO2] setpoint=%u uptime=%lus",
                     od.setpoint, (unsigned long)uptime);
        }
        uptime++;
        vTaskDelay(pdMS_TO_TICKS(PDO2_PERIOD_MS));
    }
}

#define SDO_CS_UPLOAD_REQ       0x40
#define SDO_CS_UPLOAD_RESP_4    0x43
#define SDO_CS_UPLOAD_RESP_2    0x4B
#define SDO_CS_DOWNLOAD_REQ_4   0x23
#define SDO_CS_DOWNLOAD_REQ_2   0x2B
#define SDO_CS_DOWNLOAD_RESP    0x60
#define SDO_CS_ABORT            0x80

#define SDO_ABORT_NOT_EXIST     0x06020000
#define SDO_ABORT_READ_ONLY     0x06010002

static void sdo_send_abort(uint16_t index, uint8_t subindex, uint32_t abort_code)
{
    uint8_t resp[8];
    resp[0] = SDO_CS_ABORT;
    resp[1] = index & 0xFF;
    resp[2] = (index >> 8) & 0xFF;
    resp[3] = subindex;
    resp[4] = abort_code & 0xFF;
    resp[5] = (abort_code >> 8) & 0xFF;
    resp[6] = (abort_code >> 16) & 0xFF;
    resp[7] = (abort_code >> 24) & 0xFF;
    can_send(COB_TSDO, 8, resp);
    ESP_LOGW(TAG, "[SDO] Abort index=0x%04X sub=%d code=0x%08lX",
             index, subindex, (unsigned long)abort_code);
}

static void sdo_handle(const twai_message_t *msg)
{
    if (msg->data_length_code < 4) return;

    uint8_t cs      = msg->data[0];
    uint16_t index  = (uint16_t)msg->data[1] | ((uint16_t)msg->data[2] << 8);
    uint8_t sub     = msg->data[3];

    if (cs == SDO_CS_UPLOAD_REQ) {
        uint8_t resp[8] = {0};
        resp[1] = msg->data[1];
        resp[2] = msg->data[2];
        resp[3] = sub;

        if (index == OD_HEARTBEAT_TIME_INDEX && sub == 0) {
            resp[0] = SDO_CS_UPLOAD_RESP_2;
            resp[4] = od.heartbeat_time_ms & 0xFF;
            resp[5] = (od.heartbeat_time_ms >> 8) & 0xFF;
            can_send(COB_TSDO, 8, resp);
            ESP_LOGI(TAG, "[SDO] Read 0x%04X:%d = %d ms",
                     index, sub, od.heartbeat_time_ms);

        } else if (index == OD_SENSOR_VALUE_INDEX && sub == 0) {
            resp[0] = SDO_CS_UPLOAD_RESP_2;
            resp[4] = od.sensor_value & 0xFF;
            resp[5] = (od.sensor_value >> 8) & 0xFF;
            can_send(COB_TSDO, 8, resp);
            ESP_LOGI(TAG, "[SDO] Read 0x%04X:%d = %d",
                     index, sub, od.sensor_value);

        } else if (index == OD_SETPOINT_INDEX && sub == 0) {
            resp[0] = SDO_CS_UPLOAD_RESP_2;
            resp[4] = od.setpoint & 0xFF;
            resp[5] = (od.setpoint >> 8) & 0xFF;
            can_send(COB_TSDO, 8, resp);
            ESP_LOGI(TAG, "[SDO] Read 0x%04X:%d = %d",
                     index, sub, od.setpoint);

        } else {
            sdo_send_abort(index, sub, SDO_ABORT_NOT_EXIST);
        }
        return;
    }

    if (cs == SDO_CS_DOWNLOAD_REQ_2 || cs == SDO_CS_DOWNLOAD_REQ_4) {
        uint16_t val16 = (uint16_t)msg->data[4] | ((uint16_t)msg->data[5] << 8);
        uint8_t resp[8] = {0};
        resp[0] = SDO_CS_DOWNLOAD_RESP;
        resp[1] = msg->data[1];
        resp[2] = msg->data[2];
        resp[3] = sub;

        if (index == OD_HEARTBEAT_TIME_INDEX) {
            sdo_send_abort(index, sub, SDO_ABORT_READ_ONLY);

        } else if (index == OD_SENSOR_VALUE_INDEX && sub == 0) {
            od.sensor_value = val16;
            can_send(COB_TSDO, 8, resp);
            ESP_LOGI(TAG, "[SDO] Write 0x%04X:%d = %d", index, sub, val16);

        } else if (index == OD_SETPOINT_INDEX && sub == 0) {
            od.setpoint = val16;
            can_send(COB_TSDO, 8, resp);
            ESP_LOGI(TAG, "[SDO] Write 0x%04X:%d = %d", index, sub, val16);

        } else {
            sdo_send_abort(index, sub, SDO_ABORT_NOT_EXIST);
        }
        return;
    }
}

static void nmt_handle(const twai_message_t *msg)
{
    if (msg->data_length_code < 2) return;

    uint8_t cmd     = msg->data[0];
    uint8_t target  = msg->data[1];

    if (target != 0 && target != NODE_ID) return;

    ESP_LOGW(TAG, "[NMT] cmd=0x%02X target=0x%02X", cmd, target);

    switch ((nmt_cmd_t)cmd) {
    case NMT_CMD_START:
        set_nmt_state(NMT_OPERATIONAL);
        break;
    case NMT_CMD_STOP:
        set_nmt_state(NMT_STOPPED);
        break;
    case NMT_CMD_ENTER_PREOP:
        set_nmt_state(NMT_PRE_OPERATIONAL);
        break;
    case NMT_CMD_RESET_NODE:
    case NMT_CMD_RESET_COMM:
        set_nmt_state(NMT_INITIALISING);
        vTaskDelay(pdMS_TO_TICKS(200));
        set_nmt_state(NMT_PRE_OPERATIONAL);
        break;
    default:
        ESP_LOGW(TAG, "[NMT] Unknown command 0x%02X", cmd);
        break;
    }
}

static void rx_task(void *arg)
{
    twai_message_t msg;
    ESP_LOGI(TAG, "RX task started");

    while (1) {
        if (twai_receive(&msg, pdMS_TO_TICKS(500)) != ESP_OK) continue;

        uint32_t id = msg.identifier;

        if (id == COB_NMT) {
            nmt_handle(&msg);
            continue;
        }

        if (id == COB_RSDO) {
            sdo_handle(&msg);
            continue;
        }

        if (id == COB_SYNC) {
            ESP_LOGD(TAG, "[SYNC] received");
            continue;
        }

        ESP_LOGD(TAG, "[RX] id=0x%03lX dlc=%d",
                 (unsigned long)id, msg.data_length_code);
    }
}

esp_err_t canopen_victim_init(void)
{
    nmt_mutex = xSemaphoreCreateMutex();
    if (!nmt_mutex) return ESP_ERR_NO_MEM;

    twai_general_config_t g = TWAI_GENERAL_CONFIG_DEFAULT(
        CAN_TX_GPIO, CAN_RX_GPIO, TWAI_MODE_NORMAL);
    g.rx_queue_len = 32;
    g.tx_queue_len = 16;

    twai_timing_config_t t = TWAI_TIMING_CONFIG_500KBITS();
    twai_filter_config_t f = TWAI_FILTER_CONFIG_ACCEPT_ALL();

    esp_err_t err = twai_driver_install(&g, &t, &f);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "TWAI install failed: %s", esp_err_to_name(err));
        return err;
    }
    err = twai_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "TWAI start failed: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "TWAI started (normal mode, 500 kbps)");
    ESP_LOGI(TAG, "Node-ID: 0x%02X", NODE_ID);
    ESP_LOGI(TAG, "COB-IDs: HB=0x%03X TPDO1=0x%03X TPDO2=0x%03X SDO=0x%03X",
             COB_HEARTBEAT, COB_TPDO1, COB_TPDO2, COB_TSDO);
    return ESP_OK;
}

void canopen_victim_start(void)
{
    set_nmt_state(NMT_INITIALISING);
    vTaskDelay(pdMS_TO_TICKS(100));

    uint8_t bootup = 0x00;
    can_send(COB_HEARTBEAT, 1, &bootup);
    ESP_LOGI(TAG, "Bootup message sent");

    set_nmt_state(NMT_PRE_OPERATIONAL);

    vTaskDelay(pdMS_TO_TICKS(500));
    set_nmt_state(NMT_OPERATIONAL);

    xTaskCreate(rx_task,        "can_rx",   4096, NULL, 10, NULL);
    xTaskCreate(heartbeat_task, "hb",       2048, NULL,  5, NULL);
    xTaskCreate(tpdo1_task,     "tpdo1",    2048, NULL,  5, NULL);
    xTaskCreate(tpdo2_task,     "tpdo2",    2048, NULL,  5, NULL);

    ESP_LOGI(TAG, "All tasks started - Node OPERATIONAL");
}

nmt_state_t canopen_get_nmt_state(void)
{
    return get_nmt_state();
}
