#pragma once

#define CAN_TX_GPIO         GPIO_NUM_16
#define CAN_RX_GPIO         GPIO_NUM_17

#define NODE_ID             0x01

#define COB_NMT             0x000
#define COB_SYNC            0x080
#define COB_EMCY            (0x080 + NODE_ID)
#define COB_TPDO1           (0x180 + NODE_ID)
#define COB_TPDO2           (0x280 + NODE_ID)
#define COB_TSDO            (0x580 + NODE_ID)
#define COB_RSDO            (0x600 + NODE_ID)
#define COB_HEARTBEAT       (0x700 + NODE_ID)

#define HEARTBEAT_PERIOD_MS     1000
#define PDO1_PERIOD_MS          100
#define PDO2_PERIOD_MS          500

#define OD_HEARTBEAT_TIME_INDEX     0x1017
#define OD_SENSOR_VALUE_INDEX       0x6000
#define OD_SETPOINT_INDEX           0x6001
