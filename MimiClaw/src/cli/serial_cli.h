#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the serial CLI.
 * Sets up UART and command table. Does NOT block.
 */
esp_err_t serial_cli_init(void);

/**
 * Poll for serial CLI input. Non-blocking.
 * Call from Arduino loop() or a FreeRTOS task.
 * Reads available bytes from UART, and when a full line is received,
 * parses and dispatches the command.
 */
void serial_cli_poll(void);

#ifdef __cplusplus
}
#endif
