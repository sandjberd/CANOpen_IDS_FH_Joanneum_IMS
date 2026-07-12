idf_component_register(
    SRCS "main.c" "canopen_victim.c"
    INCLUDE_DIRS "."
    REQUIRES driver esp_timer
)
