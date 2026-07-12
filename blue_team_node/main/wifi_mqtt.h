#pragma once
#include "esp_err.h"
#include "ids_engine.h"

esp_err_t wifi_init_sta(void);
esp_err_t mqtt_start(void);
void mqtt_publish_alert(const ids_alert_t *alert);
