#pragma once
#include "esp_err.h"
#include <stdint.h>

typedef enum {
    NMT_INITIALISING    = 0x00,
    NMT_PRE_OPERATIONAL = 0x7F,
    NMT_OPERATIONAL     = 0x05,
    NMT_STOPPED         = 0x04,
} nmt_state_t;

typedef enum {
    NMT_CMD_START           = 0x01,
    NMT_CMD_STOP            = 0x02,
    NMT_CMD_ENTER_PREOP     = 0x80,
    NMT_CMD_RESET_NODE      = 0x81,
    NMT_CMD_RESET_COMM      = 0x82,
} nmt_cmd_t;

esp_err_t canopen_victim_init(void);
void canopen_victim_start(void);
nmt_state_t canopen_get_nmt_state(void);
