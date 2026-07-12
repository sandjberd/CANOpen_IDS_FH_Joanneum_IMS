#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

esp_err_t can_attack_init(void);
void can_stop_attack(void);
bool can_attack_is_active(void);

esp_err_t can_send_fake_emcy(uint16_t error_code, uint8_t error_register);
void can_start_emcy_flood(uint32_t interval_ms);

esp_err_t can_send_nmt(uint8_t command_specifier);

esp_err_t can_sdo_read(uint16_t index, uint8_t subindex);
esp_err_t can_sdo_write_u16(uint16_t index, uint8_t subindex, uint16_t value);
void can_start_sdo_flood(uint32_t interval_ms);

esp_err_t can_send_pdo_spoof(uint32_t cob_id, const uint8_t payload[8]);
void can_start_pdo_flood(uint32_t interval_ms);

esp_err_t can_send_heartbeat(uint8_t node_id, uint8_t state);
void can_start_hb_spoof(uint8_t state, uint32_t interval_ms);
void can_start_hb_ghost(uint8_t node_id, uint32_t interval_ms);

esp_err_t can_lss_set_node_id(uint8_t new_node_id);
esp_err_t can_lss_set_bitrate(uint8_t table_index);

void can_start_dos_flood(uint32_t interval_us);
