#pragma once

#include "mimi_init.h"

class MimiClaw {
public:
    /**
     * Initialize all MimiClaw subsystems.
     * Call once from Arduino setup().
     * @return true on success
     */
    bool begin();

    /**
     * Start WiFi and all network-dependent services.
     * Call once from Arduino setup() after begin().
     * @return true on success
     */
    bool start();

    /**
     * Poll serial CLI for input.
     * Call from Arduino loop(). Non-blocking.
     */
    void loop();
};
