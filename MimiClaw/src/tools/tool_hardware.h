#pragma once

#include "esp_err.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Configure a GPIO pin as input or output with optional pull resistor.
 * Input JSON: {"pin": <int>, "mode": "input"|"output"|"input_pullup"|"input_pulldown"}
 */
esp_err_t tool_gpio_set_mode_execute(const char *input_json, char *output, size_t output_size);

/**
 * Write a digital value to a GPIO pin.
 * Input JSON: {"pin": <int>, "state": 0|1}
 */
esp_err_t tool_gpio_write_execute(const char *input_json, char *output, size_t output_size);

/**
 * Read the digital value of a GPIO pin.
 * Input JSON: {"pin": <int>}
 */
esp_err_t tool_gpio_read_execute(const char *input_json, char *output, size_t output_size);

/**
 * Write a PWM signal to a pin using LEDC.
 * Input JSON: {"pin": <int>, "duty": 0-255, "freq_hz": <int>}
 */
esp_err_t tool_pwm_write_execute(const char *input_json, char *output, size_t output_size);

/**
 * Read an analog value from a pin using ADC.
 * Input JSON: {"pin": <int>}
 */
esp_err_t tool_adc_read_execute(const char *input_json, char *output, size_t output_size);

/**
 * Scan an I2C bus for connected devices.
 * Input JSON: {"sda": <int>, "scl": <int>}
 */
esp_err_t tool_i2c_scan_execute(const char *input_json, char *output, size_t output_size);

/**
 * Write bytes to an I2C device and optionally read back.
 * Input JSON: {"addr": <int>, "write_bytes": "<hex>", "read_len": <int>, "sda": <int>, "scl": <int>}
 */
esp_err_t tool_i2c_write_read_execute(const char *input_json, char *output, size_t output_size);

/**
 * Full-duplex SPI transfer.
 * Input JSON: {"mosi": <int>, "miso": <int>, "sclk": <int>, "cs": <int>, "data": "<hex>"}
 */
esp_err_t tool_spi_transfer_execute(const char *input_json, char *output, size_t output_size);

/**
 * Send data over UART port 1 or 2.
 * Input JSON: {"port": 1|2, "tx": <int>, "rx": <int>, "baud": <int>, "data": "<hex or text>"}
 */
esp_err_t tool_uart_write_execute(const char *input_json, char *output, size_t output_size);

/**
 * Read available data from UART port 1 or 2.
 * Input JSON: {"port": 1|2, "timeout_ms": <int>}
 */
esp_err_t tool_uart_read_execute(const char *input_json, char *output, size_t output_size);

#ifdef __cplusplus
}
#endif
