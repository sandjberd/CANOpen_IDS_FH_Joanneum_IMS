#pragma once

#define WIFI_SSID           "MYWIFI"
#define WIFI_PASSWORD       "nonyabusiness"
#define WIFI_MAX_RETRY      10

#define MQTT_BROKER_URI     "mqtt://10.0.0.99:1883"
#define MQTT_ALERT_TOPIC    "blueteam/alerts"
#define MQTT_TRAFFIC_TOPIC  "blueteam/traffic"
#define MQTT_HEARTBEAT_TOPIC "blueteam/heartbeat"

#define CAN_TX_GPIO         GPIO_NUM_16
#define CAN_RX_GPIO         GPIO_NUM_17
#define CAN_BITRATE_KBPS    500

#define MAX_LEGIT_NODES     8

#define NMT_COB             0x000
#define SYNC_COB            0x080
#define EMCY_BASE           0x080
#define EMCY_COB(node)      (EMCY_BASE + (node))
#define HEARTBEAT_BASE      0x700
#define HEARTBEAT_COB(node) (HEARTBEAT_BASE + (node))
#define TPDO1_BASE          0x180
#define TPDO1_COB(node)     (TPDO1_BASE + (node))
#define TPDO2_BASE          0x280
#define TPDO2_COB(node)     (TPDO2_BASE + (node))
#define SDO_TX_BASE         0x580
#define SDO_TX_COB(node)    (SDO_TX_BASE + (node))
#define SDO_RX_BASE         0x600
#define SDO_RX_COB(node)    (SDO_RX_BASE + (node))
#define LSS_MASTER_COB      0x7E5
#define LSS_SLAVE_COB       0x7E4

#define EMCY_RATE_WINDOW_MS     1000
#define EMCY_RATE_THRESHOLD     3
#define EMCY_MIN_INTERVAL_MS    50

#define HEARTBEAT_TIMEOUT_MS    2000
#define HEARTBEAT_PERIOD_MS     1000
#define HEARTBEAT_MIN_INTERVAL_MS 200

#define NMT_STATE_BOOTUP        0x00
#define NMT_STATE_STOPPED       0x04
#define NMT_STATE_OPERATIONAL   0x05
#define NMT_STATE_PREOP         0x7F

#define SDO_RATE_WINDOW_MS      1000
#define SDO_RATE_THRESHOLD      10
#define SDO_CCS_DOWNLOAD_MASK   0x20
#define SDO_CCS_UPLOAD          0x40
#define SDO_SCS_ABORT           0x80

#define TPDO1_PERIOD_MS         100
#define TPDO2_PERIOD_MS         500
#define PDO_EARLY_FACTOR_PCT    50

#define BUSLOAD_WINDOW_MS       1000
#define BUSLOAD_ID_THRESHOLD    200
#define BUSLOAD_TOTAL_THRESHOLD 1500

typedef enum {
    ALERT_INFO = 0,
    ALERT_WARNING,
    ALERT_CRITICAL,
} alert_severity_t;
