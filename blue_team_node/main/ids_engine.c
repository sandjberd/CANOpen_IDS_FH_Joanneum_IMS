#include "ids_engine.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "IDS";

static ids_mode_t g_mode = IDS_MODE_B;

typedef struct {
    uint8_t node_id;
    bool active;

    uint64_t last_heartbeat_us;
    uint8_t  last_hb_state;
    bool     hb_seen;

    uint32_t emcy_count_window;
    uint64_t emcy_window_start_us;
    uint64_t last_emcy_us;

    uint32_t sdo_count_window;
    uint64_t sdo_window_start_us;

    uint64_t last_tpdo1_us;
    uint64_t last_tpdo2_us;
} node_state_t;

static node_state_t nodes[MAX_LEGIT_NODES];
static int node_count = 0;

typedef struct {
    uint32_t cob_id;
    uint32_t count_window;
    uint64_t window_start_us;
    bool     alerted_this_window;
    bool     used;
} cob_load_t;

#define MAX_TRACKED_COBS 32
static cob_load_t cob_load[MAX_TRACKED_COBS];

static uint32_t total_count_window = 0;
static uint64_t total_window_start_us = 0;
static bool     total_alerted_this_window = false;

void ids_init(void)
{
    memset(nodes, 0, sizeof(nodes));
    memset(cob_load, 0, sizeof(cob_load));
    node_count = 0;
    total_count_window = 0;
    total_window_start_us = 0;
    total_alerted_this_window = false;
    g_mode = IDS_MODE_B;
    ESP_LOGI(TAG, "IDS engine initialized");
}

void ids_set_mode(ids_mode_t mode)
{
    g_mode = mode;
    ESP_LOGI(TAG, "IDS mode set to %s", mode == IDS_MODE_A ? "A (transport)" : "B (CANopen-aware)");
}

void ids_whitelist_add(uint8_t node_id)
{
    if (node_count >= MAX_LEGIT_NODES) {
        ESP_LOGE(TAG, "Whitelist full");
        return;
    }
    nodes[node_count].node_id = node_id;
    nodes[node_count].active = true;
    nodes[node_count].last_heartbeat_us = esp_timer_get_time();
    node_count++;
    ESP_LOGI(TAG, "Whitelisted node 0x%02X", node_id);
}

static node_state_t *find_node(uint8_t node_id)
{
    for (int i = 0; i < node_count; i++) {
        if (nodes[i].node_id == node_id) return &nodes[i];
    }
    return NULL;
}

static void fill_alert(ids_alert_t *a, const char *rule, const char *desc,
                      alert_severity_t sev, uint8_t node, uint16_t cob)
{
    strncpy(a->rule, rule, sizeof(a->rule) - 1);
    a->rule[sizeof(a->rule) - 1] = 0;
    strncpy(a->description, desc, sizeof(a->description) - 1);
    a->description[sizeof(a->description) - 1] = 0;
    a->severity = sev;
    a->suspect_node_id = node;
    a->suspect_cob_id = cob;
    a->timestamp_us = esp_timer_get_time();
}

bool ids_check_emcy(const emcy_event_t *evt, ids_alert_t *out_alert)
{
    char desc[128];
    uint16_t cob = EMCY_COB(evt->node_id);

    node_state_t *n = find_node(evt->node_id);
    if (!n) {
        snprintf(desc, sizeof(desc),
            "EMCY from non-whitelisted Node-ID 0x%02X (COB 0x%03X) code=0x%04X",
            evt->node_id, cob, evt->error_code);
        fill_alert(out_alert, "R1_UNKNOWN_NODE_EMCY", desc,
                   ALERT_CRITICAL, evt->node_id, cob);
        return true;
    }

    uint64_t now = evt->timestamp_us;
    if (now - n->emcy_window_start_us > EMCY_RATE_WINDOW_MS * 1000ULL) {
        n->emcy_window_start_us = now;
        n->emcy_count_window = 0;
    }
    n->emcy_count_window++;

    if (n->emcy_count_window > EMCY_RATE_THRESHOLD) {
        snprintf(desc, sizeof(desc),
            "EMCY flood from Node-ID 0x%02X: %lu EMCY in %d ms (threshold %d)",
            evt->node_id, (unsigned long)n->emcy_count_window,
            EMCY_RATE_WINDOW_MS, EMCY_RATE_THRESHOLD);
        fill_alert(out_alert, "R2_EMCY_FLOOD", desc,
                   ALERT_CRITICAL, evt->node_id, cob);
        return true;
    }

    if (n->last_emcy_us != 0) {
        uint64_t delta_ms = (now - n->last_emcy_us) / 1000;
        if (delta_ms < EMCY_MIN_INTERVAL_MS) {
            snprintf(desc, sizeof(desc),
                "EMCY inter-arrival %llu ms < %d ms from Node-ID 0x%02X",
                (unsigned long long)delta_ms, EMCY_MIN_INTERVAL_MS, evt->node_id);
            fill_alert(out_alert, "R3_EMCY_TIMING", desc,
                       ALERT_WARNING, evt->node_id, cob);
            n->last_emcy_us = now;
            return true;
        }
    }
    n->last_emcy_us = now;

    uint16_t ec = evt->error_code;
    bool suspicious_code = false;
    if (ec >= 0xFF00) suspicious_code = true;
    if (suspicious_code) {
        snprintf(desc, sizeof(desc),
            "Suspicious EMCY error code 0x%04X from Node-ID 0x%02X",
            ec, evt->node_id);
        fill_alert(out_alert, "R4_BAD_ERROR_CODE", desc,
                   ALERT_WARNING, evt->node_id, cob);
        return true;
    }

    if (evt->raw_data[3] == 0xDE && evt->raw_data[4] == 0xAD &&
        evt->raw_data[5] == 0xBE && evt->raw_data[6] == 0xEF) {
        snprintf(desc, sizeof(desc),
            "Attacker signature in EMCY manuf-bytes from Node-ID 0x%02X",
            evt->node_id);
        fill_alert(out_alert, "R5_SIGNATURE_MATCH", desc,
                   ALERT_CRITICAL, evt->node_id, cob);
        return true;
    }

    return false;
}

bool ids_check_heartbeat(uint8_t node_id, uint8_t state_byte,
                         uint64_t timestamp_us, ids_alert_t *out_alert)
{
    char desc[128];
    uint16_t cob = HEARTBEAT_COB(node_id);
    node_state_t *n = find_node(node_id);

    if (!n) {
        snprintf(desc, sizeof(desc),
            "Heartbeat from non-whitelisted Node-ID 0x%02X (COB 0x%03X) state=0x%02X -- ghost node",
            node_id, cob, state_byte);
        fill_alert(out_alert, "R6a_GHOST_NODE", desc,
                   ALERT_CRITICAL, node_id, cob);
        return true;
    }

    bool fired = false;

    if (n->hb_seen) {
        uint64_t delta_ms = (timestamp_us - n->last_heartbeat_us) / 1000;
        if (delta_ms < HEARTBEAT_MIN_INTERVAL_MS) {
            snprintf(desc, sizeof(desc),
                "Heartbeat inter-arrival %llu ms < %d ms for Node 0x%02X -- second producer (spoof)",
                (unsigned long long)delta_ms, HEARTBEAT_MIN_INTERVAL_MS, node_id);
            fill_alert(out_alert, "R6b_HEARTBEAT_SPOOF", desc,
                       ALERT_CRITICAL, node_id, cob);
            fired = true;
        }
    }

    if (!fired) {
        if (state_byte != NMT_STATE_BOOTUP &&
            state_byte != NMT_STATE_STOPPED &&
            state_byte != NMT_STATE_OPERATIONAL &&
            state_byte != NMT_STATE_PREOP) {
            snprintf(desc, sizeof(desc),
                "Invalid NMT state 0x%02X in heartbeat from Node 0x%02X -- false state",
                state_byte, node_id);
            fill_alert(out_alert, "R6c_HEARTBEAT_STATE", desc,
                       ALERT_WARNING, node_id, cob);
            fired = true;
        }
    }

    n->last_heartbeat_us = timestamp_us;
    n->last_hb_state = state_byte;
    n->hb_seen = true;

    return fired;
}

bool ids_check_nmt(const can_frame_t *f, ids_alert_t *out_alert)
{
    char desc[128];
    if (f->cob_id != NMT_COB) return false;
    if (f->dlc < 2) return false;

    uint8_t cs     = f->data[0];
    uint8_t target = f->data[1];

    const char *name = "unknown";
    bool known = true;
    switch (cs) {
        case 0x01: name = "start";          break;
        case 0x02: name = "stop";           break;
        case 0x80: name = "enter pre-op";   break;
        case 0x81: name = "reset node";     break;
        case 0x82: name = "reset comm";     break;
        default:   known = false;           break;
    }

    if (!known) {
        snprintf(desc, sizeof(desc),
            "NMT frame with unknown command specifier 0x%02X (target 0x%02X)",
            cs, target);
        fill_alert(out_alert, "R_NMT_BAD_CS", desc,
                   ALERT_WARNING, target, NMT_COB);
        return true;
    }

    alert_severity_t sev = (cs == 0x02 || cs == 0x81 || cs == 0x82)
                           ? ALERT_CRITICAL : ALERT_WARNING;
    snprintf(desc, sizeof(desc),
        "NMT '%s' (cs=0x%02X) for target 0x%02X observed on bus",
        name, cs, target);
    fill_alert(out_alert, "R_NMT_CONTROL", desc, sev, target, NMT_COB);
    return true;
}

bool ids_check_sdo(const can_frame_t *f, ids_alert_t *out_alert)
{
    char desc[128];
    bool is_req  = (f->cob_id >= SDO_RX_BASE + 1 && f->cob_id <= SDO_RX_BASE + 0x7F);
    bool is_resp = (f->cob_id >= SDO_TX_BASE + 1 && f->cob_id <= SDO_TX_BASE + 0x7F);
    if (!is_req && !is_resp) return false;
    if (f->dlc < 1) return false;

    uint8_t node_id = is_req ? (uint8_t)(f->cob_id - SDO_RX_BASE)
                             : (uint8_t)(f->cob_id - SDO_TX_BASE);
    uint8_t cmd = f->data[0];
    uint16_t index = 0;
    if (f->dlc >= 3) index = (uint16_t)f->data[1] | ((uint16_t)f->data[2] << 8);

    node_state_t *n = find_node(node_id);

    if (!n) {
        snprintf(desc, sizeof(desc),
            "SDO on non-whitelisted Node-ID 0x%02X (COB 0x%03lX) cmd=0x%02X index=0x%04X",
            node_id, (unsigned long)f->cob_id, cmd, index);
        fill_alert(out_alert, "R7a_SDO_UNKNOWN_NODE", desc,
                   ALERT_CRITICAL, node_id, (uint16_t)f->cob_id);
        return true;
    }

    if (is_resp && cmd == SDO_SCS_ABORT) {
        snprintf(desc, sizeof(desc),
            "SDO abort (0x80) from Node 0x%02X index=0x%04X -- refused access attempt",
            node_id, index);
        fill_alert(out_alert, "R7b_SDO_ABORT", desc,
                   ALERT_WARNING, node_id, (uint16_t)f->cob_id);
        return true;
    }

    if (is_req) {
        uint64_t now = f->timestamp_us;
        if (now - n->sdo_window_start_us > SDO_RATE_WINDOW_MS * 1000ULL) {
            n->sdo_window_start_us = now;
            n->sdo_count_window = 0;
        }
        n->sdo_count_window++;
        if (n->sdo_count_window > SDO_RATE_THRESHOLD) {
            snprintf(desc, sizeof(desc),
                "SDO flood on Node 0x%02X: %lu req in %d ms (threshold %d)",
                node_id, (unsigned long)n->sdo_count_window,
                SDO_RATE_WINDOW_MS, SDO_RATE_THRESHOLD);
            fill_alert(out_alert, "R8_SDO_FLOOD", desc,
                       ALERT_CRITICAL, node_id, (uint16_t)f->cob_id);
            return true;
        }

        bool is_write = (cmd & 0xE0) == SDO_CCS_DOWNLOAD_MASK;
        bool is_read  = (cmd == SDO_CCS_UPLOAD);
        if (is_write || is_read) {
            snprintf(desc, sizeof(desc),
                "Unsolicited SDO %s on Node 0x%02X index=0x%04X cmd=0x%02X",
                is_write ? "write" : "read", node_id, index, cmd);
            fill_alert(out_alert, "R7c_SDO_ACCESS", desc,
                       ALERT_WARNING, node_id, (uint16_t)f->cob_id);
            return true;
        }
    }

    return false;
}

bool ids_check_pdo(const can_frame_t *f, ids_alert_t *out_alert)
{
    char desc[128];
    bool is_tpdo1 = (f->cob_id >= TPDO1_BASE + 1 && f->cob_id <= TPDO1_BASE + 0x7F);
    bool is_tpdo2 = (f->cob_id >= TPDO2_BASE + 1 && f->cob_id <= TPDO2_BASE + 0x7F);
    if (!is_tpdo1 && !is_tpdo2) return false;

    uint8_t node_id = is_tpdo1 ? (uint8_t)(f->cob_id - TPDO1_BASE)
                               : (uint8_t)(f->cob_id - TPDO2_BASE);
    node_state_t *n = find_node(node_id);
    if (!n) {
        snprintf(desc, sizeof(desc),
            "PDO from non-whitelisted Node-ID 0x%02X (COB 0x%03lX) -- spoofed source",
            node_id, (unsigned long)f->cob_id);
        fill_alert(out_alert, "R_PDO_UNKNOWN_NODE", desc,
                   ALERT_WARNING, node_id, (uint16_t)f->cob_id);
        return true;
    }

    uint64_t now = f->timestamp_us;
    uint64_t *last = is_tpdo1 ? &n->last_tpdo1_us : &n->last_tpdo2_us;
    uint32_t period_ms = is_tpdo1 ? TPDO1_PERIOD_MS : TPDO2_PERIOD_MS;
    uint32_t min_gap_ms = (period_ms * PDO_EARLY_FACTOR_PCT) / 100;

    if (*last != 0) {
        uint64_t delta_ms = (now - *last) / 1000;
        if (delta_ms < min_gap_ms) {
            snprintf(desc, sizeof(desc),
                "TPDO%d on Node 0x%02X arrived %llu ms apart (< %lu ms) -- injected frame",
                is_tpdo1 ? 1 : 2, node_id,
                (unsigned long long)delta_ms, (unsigned long)min_gap_ms);
            fill_alert(out_alert, "R_PDO_INJECT", desc,
                       ALERT_WARNING, node_id, (uint16_t)f->cob_id);
            *last = now;
            return true;
        }
    }
    *last = now;
    return false;
}

bool ids_check_lss(const can_frame_t *f, ids_alert_t *out_alert)
{
    char desc[128];
    if (f->cob_id != LSS_MASTER_COB) return false;
    if (f->dlc < 1) return false;

    uint8_t cs = f->data[0];
    const char *name = "LSS command";
    if (cs == 0x11) name = "configure Node-ID";
    else if (cs == 0x13) name = "configure bitrate";
    else if (cs == 0x04) name = "switch mode global";
    else if (cs == 0x15) name = "store configuration";
    else if (cs == 0x17) name = "activate bitrate";

    snprintf(desc, sizeof(desc),
        "LSS master frame during operation: %s (cs=0x%02X) -- commissioning service abused",
        name, cs);
    fill_alert(out_alert, "R_LSS_ABUSE", desc,
               ALERT_CRITICAL, 0, LSS_MASTER_COB);
    return true;
}

static cob_load_t *find_or_alloc_cob(uint32_t cob_id, uint64_t now)
{
    cob_load_t *free_slot = NULL;
    for (int i = 0; i < MAX_TRACKED_COBS; i++) {
        if (cob_load[i].used && cob_load[i].cob_id == cob_id) return &cob_load[i];
        if (!cob_load[i].used && !free_slot) free_slot = &cob_load[i];
    }
    if (free_slot) {
        free_slot->used = true;
        free_slot->cob_id = cob_id;
        free_slot->count_window = 0;
        free_slot->window_start_us = now;
        free_slot->alerted_this_window = false;
        return free_slot;
    }
    cob_load_t *evict = &cob_load[0];
    for (int i = 1; i < MAX_TRACKED_COBS; i++) {
        if (cob_load[i].count_window < evict->count_window) evict = &cob_load[i];
    }
    evict->cob_id = cob_id;
    evict->count_window = 0;
    evict->window_start_us = now;
    evict->alerted_this_window = false;
    return evict;
}

bool ids_check_busload(const can_frame_t *f, ids_alert_t *out_alert)
{
    char desc[128];
    uint64_t now = f->timestamp_us;

    if (now - total_window_start_us > BUSLOAD_WINDOW_MS * 1000ULL) {
        total_window_start_us = now;
        total_count_window = 0;
        total_alerted_this_window = false;
    }
    total_count_window++;

    cob_load_t *c = find_or_alloc_cob(f->cob_id, now);
    if (now - c->window_start_us > BUSLOAD_WINDOW_MS * 1000ULL) {
        c->window_start_us = now;
        c->count_window = 0;
        c->alerted_this_window = false;
    }
    c->count_window++;

    if (!c->alerted_this_window && c->count_window > BUSLOAD_ID_THRESHOLD) {
        c->alerted_this_window = true;
        snprintf(desc, sizeof(desc),
            "Bus flood: COB 0x%03lX at %lu frames/%d ms (threshold %d) -- DoS",
            (unsigned long)f->cob_id, (unsigned long)c->count_window,
            BUSLOAD_WINDOW_MS, BUSLOAD_ID_THRESHOLD);
        fill_alert(out_alert, "R_BUS_FLOOD_ID", desc,
                   ALERT_CRITICAL, 0, (uint16_t)f->cob_id);
        return true;
    }

    if (!total_alerted_this_window && total_count_window > BUSLOAD_TOTAL_THRESHOLD) {
        total_alerted_this_window = true;
        snprintf(desc, sizeof(desc),
            "Bus saturation: %lu total frames/%d ms (threshold %d) -- DoS",
            (unsigned long)total_count_window, BUSLOAD_WINDOW_MS,
            BUSLOAD_TOTAL_THRESHOLD);
        fill_alert(out_alert, "R_BUS_FLOOD_TOTAL", desc,
                   ALERT_CRITICAL, 0, (uint16_t)f->cob_id);
        return true;
    }

    return false;
}

int ids_periodic_check(ids_alert_t *out_alerts, int max_alerts)
{
    int count = 0;
    uint64_t now = esp_timer_get_time();
    char desc[128];

    for (int i = 0; i < node_count && count < max_alerts; i++) {
        node_state_t *n = &nodes[i];
        if (!n->active) continue;
        uint64_t delta_ms = (now - n->last_heartbeat_us) / 1000;
        if (delta_ms > HEARTBEAT_TIMEOUT_MS) {
            snprintf(desc, sizeof(desc),
                "Heartbeat from Node 0x%02X missing for %llu ms -- possible suppression/impersonation",
                n->node_id, (unsigned long long)delta_ms);
            fill_alert(&out_alerts[count], "R6_HEARTBEAT_LOST", desc,
                       ALERT_CRITICAL, n->node_id, HEARTBEAT_COB(n->node_id));
            count++;
            n->last_heartbeat_us = now;
        }
    }
    return count;
}
