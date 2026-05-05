#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize MimiClaw core infrastructure and all subsystems.
 * Call from Arduino setup() before mimi_start().
 *
 * Initializes: NVS, event loop (guarded), SPIFFS, message bus, memory,
 * skills, sessions, WiFi, proxy, Telegram, LLM, tools, cron, heartbeat,
 * agent loop, and serial CLI.
 */
esp_err_t mimi_init(void);

/**
 * Start MimiClaw network services.
 * Call from Arduino setup() after mimi_init().
 *
 * Connects WiFi, starts outbound dispatch, agent loop, Telegram bot,
 * cron scheduler, heartbeat timer, and WebSocket server.
 */
esp_err_t mimi_start(void);

/**
 * Poll MimiClaw serial CLI. Call from Arduino loop().
 * Non-blocking: returns immediately if no input available.
 */
void mimi_loop(void);

#ifdef __cplusplus
}
#endif
