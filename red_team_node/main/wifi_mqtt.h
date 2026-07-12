#pragma once
#include "esp_err.h"

esp_err_t wifi_init_sta_hidden(void);
esp_err_t mqtt_start(void);
void mqtt_publish_status(const char *msg);
