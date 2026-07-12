#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "config.h"

typedef struct {
    uint8_t node_id;
    uint16_t error_code;
    uint8_t error_register;
    uint64_t timestamp_us;
    uint8_t raw_data[8];
} emcy_event_t;

typedef struct {
    uint32_t cob_id;
    uint8_t  dlc;
    uint8_t  data[8];
    uint64_t timestamp_us;
} can_frame_t;

typedef struct {
    char rule[32];
    char description[128];
    alert_severity_t severity;
    uint8_t suspect_node_id;
    uint16_t suspect_cob_id;
    uint64_t timestamp_us;
} ids_alert_t;

typedef enum {
    IDS_MODE_A = 0,
    IDS_MODE_B = 1,
} ids_mode_t;

void ids_init(void);
void ids_set_mode(ids_mode_t mode);
void ids_whitelist_add(uint8_t node_id);

bool ids_check_emcy(const emcy_event_t *evt, ids_alert_t *out_alert);
bool ids_check_heartbeat(uint8_t node_id, uint8_t state_byte,
                         uint64_t timestamp_us, ids_alert_t *out_alert);
bool ids_check_nmt(const can_frame_t *f, ids_alert_t *out_alert);
bool ids_check_sdo(const can_frame_t *f, ids_alert_t *out_alert);
bool ids_check_pdo(const can_frame_t *f, ids_alert_t *out_alert);
bool ids_check_lss(const can_frame_t *f, ids_alert_t *out_alert);
bool ids_check_busload(const can_frame_t *f, ids_alert_t *out_alert);
int ids_periodic_check(ids_alert_t *out_alerts, int max_alerts);
