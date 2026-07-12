#pragma once

#define WIFI_SSID           "MYWIFI"
#define WIFI_PASSWORD       "nonyabusiness"
#define WIFI_MAX_RETRY      10

#define MQTT_BROKER_URI     "mqtt://10.0.0.99:1883"
#define MQTT_CMD_TOPIC      "redteam/cmd"
#define MQTT_STATUS_TOPIC   "redteam/status"

#define CAN_TX_GPIO         GPIO_NUM_16
#define CAN_RX_GPIO         GPIO_NUM_17
#define CAN_BITRATE_KBPS    500

#define VICTIM_NODE_ID      0x01
#define GHOST_NODE_ID       0x7E

#define NMT_COB_ID                 0x000
#define SYNC_COB_ID                0x080
#define EMCY_COB_ID(node)          (0x080 + (node))
#define TPDO1_COB_ID(node)         (0x180 + (node))
#define TPDO2_COB_ID(node)         (0x280 + (node))
#define SDO_RX_COB_ID(node)        (0x600 + (node))
#define SDO_TX_COB_ID(node)        (0x580 + (node))
#define HEARTBEAT_COB_ID(node)     (0x700 + (node))
#define LSS_MASTER_COB_ID          0x7E5
#define LSS_SLAVE_COB_ID           0x7E4

#define NMT_CS_START_NODE          0x01
#define NMT_CS_STOP_NODE           0x02
#define NMT_CS_ENTER_PREOP         0x80
#define NMT_CS_RESET_NODE          0x81
#define NMT_CS_RESET_COMM          0x82

#define OD_HEARTBEAT_TIME_INDEX    0x1017
#define OD_SENSOR_VALUE_INDEX      0x6000
#define OD_SETPOINT_INDEX          0x6001

#define SDO_CCS_UPLOAD             0x40
#define SDO_CCS_DOWNLOAD_2B        0x2B
#define SDO_CS_ABORT               0x80

#define ATTACK_EMCY_FAKE           "emcy_fake"
#define ATTACK_EMCY_OVERVOLT       "emcy_overvolt"
#define ATTACK_EMCY_FLOOD          "emcy_flood"
#define ATTACK_NMT_PREOP           "nmt_preop"
#define ATTACK_NMT_STOP            "nmt_stop"
#define ATTACK_NMT_RESET           "nmt_reset"
#define ATTACK_SDO_READ_RO         "sdo_read_ro"
#define ATTACK_SDO_WRITE_SP        "sdo_write_sp"
#define ATTACK_SDO_WRITE_RO        "sdo_write_ro"
#define ATTACK_SDO_FLOOD           "sdo_flood"
#define ATTACK_PDO_SPOOF           "pdo_spoof"
#define ATTACK_PDO_FLOOD           "pdo_flood"
#define ATTACK_HB_SPOOF            "hb_spoof"
#define ATTACK_HB_GHOST            "hb_ghost"
#define ATTACK_LSS_SWITCH          "lss_switch"
#define ATTACK_LSS_BITRATE         "lss_bitrate"
#define ATTACK_DOS_FLOOD           "dos_flood"
#define ATTACK_STOP                "stop"
