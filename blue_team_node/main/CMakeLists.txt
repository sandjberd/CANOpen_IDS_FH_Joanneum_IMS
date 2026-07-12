idf_component_register(
    SRCS "main.c" "wifi_mqtt.c" "can_monitor.c" "ids_engine.c"
    INCLUDE_DIRS "."
    REQUIRES driver esp_wifi esp_event nvs_flash mqtt esp_netif esp_timer
)
