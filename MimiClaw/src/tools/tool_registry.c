#include "tool_registry.h"
#include "mimi_config.h"
#include "tools/tool_web_search.h"
#include "tools/tool_get_time.h"
#include "tools/tool_files.h"
#include "tools/tool_cron.h"
#include "tools/tool_hardware.h"

#include <string.h>
#include "esp_log.h"
#include "cJSON.h"

static const char *TAG = "tools";

#define MAX_TOOLS 24

static mimi_tool_t s_tools[MAX_TOOLS];
static int s_tool_count = 0;
static char *s_tools_json = NULL;  /* cached JSON array string */

static void register_tool(const mimi_tool_t *tool)
{
    if (s_tool_count >= MAX_TOOLS) {
        ESP_LOGE(TAG, "Tool registry full");
        return;
    }
    s_tools[s_tool_count++] = *tool;
    ESP_LOGI(TAG, "Registered tool: %s", tool->name);
}

static void build_tools_json(void)
{
    cJSON *arr = cJSON_CreateArray();

    for (int i = 0; i < s_tool_count; i++) {
        cJSON *tool = cJSON_CreateObject();
        cJSON_AddStringToObject(tool, "name", s_tools[i].name);
        cJSON_AddStringToObject(tool, "description", s_tools[i].description);

        cJSON *schema = cJSON_Parse(s_tools[i].input_schema_json);
        if (schema) {
            cJSON_AddItemToObject(tool, "input_schema", schema);
        }

        cJSON_AddItemToArray(arr, tool);
    }

    free(s_tools_json);
    s_tools_json = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);

    ESP_LOGI(TAG, "Tools JSON built (%d tools)", s_tool_count);
}

esp_err_t tool_registry_init(void)
{
    s_tool_count = 0;

    /* Register web_search */
    tool_web_search_init();

    mimi_tool_t ws = {
        .name = "web_search",
        .description = "Search the web for current information. Use this when you need up-to-date facts, news, weather, or anything beyond your training data.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{\"query\":{\"type\":\"string\",\"description\":\"The search query\"}},"
            "\"required\":[\"query\"]}",
        .execute = tool_web_search_execute,
    };
    register_tool(&ws);

    /* Register get_current_time */
    mimi_tool_t gt = {
        .name = "get_current_time",
        .description = "Get the current date and time. Also sets the system clock. Call this when you need to know what time or date it is.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{},"
            "\"required\":[]}",
        .execute = tool_get_time_execute,
    };
    register_tool(&gt);

    /* Register read_file */
    mimi_tool_t rf = {
        .name = "read_file",
        .description = "Read a file from SPIFFS storage. Path must start with " MIMI_SPIFFS_BASE "/.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{\"path\":{\"type\":\"string\",\"description\":\"Absolute path starting with " MIMI_SPIFFS_BASE "/\"}},"
            "\"required\":[\"path\"]}",
        .execute = tool_read_file_execute,
    };
    register_tool(&rf);

    /* Register write_file */
    mimi_tool_t wf = {
        .name = "write_file",
        .description = "Write or overwrite a file on SPIFFS storage. Path must start with " MIMI_SPIFFS_BASE "/.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{\"path\":{\"type\":\"string\",\"description\":\"Absolute path starting with " MIMI_SPIFFS_BASE "/\"},"
            "\"content\":{\"type\":\"string\",\"description\":\"File content to write\"}},"
            "\"required\":[\"path\",\"content\"]}",
        .execute = tool_write_file_execute,
    };
    register_tool(&wf);

    /* Register edit_file */
    mimi_tool_t ef = {
        .name = "edit_file",
        .description = "Find and replace text in a file on SPIFFS. Replaces first occurrence of old_string with new_string.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{\"path\":{\"type\":\"string\",\"description\":\"Absolute path starting with " MIMI_SPIFFS_BASE "/\"},"
            "\"old_string\":{\"type\":\"string\",\"description\":\"Text to find\"},"
            "\"new_string\":{\"type\":\"string\",\"description\":\"Replacement text\"}},"
            "\"required\":[\"path\",\"old_string\",\"new_string\"]}",
        .execute = tool_edit_file_execute,
    };
    register_tool(&ef);

    /* Register list_dir */
    mimi_tool_t ld = {
        .name = "list_dir",
        .description = "List files on SPIFFS storage, optionally filtered by path prefix.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{\"prefix\":{\"type\":\"string\",\"description\":\"Optional path prefix filter, e.g. " MIMI_SPIFFS_BASE "/memory/\"}},"
            "\"required\":[]}",
        .execute = tool_list_dir_execute,
    };
    register_tool(&ld);

    /* Register cron_add */
    mimi_tool_t ca = {
        .name = "cron_add",
        .description = "Schedule a recurring or one-shot task. The message will trigger an agent turn when the job fires.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"name\":{\"type\":\"string\",\"description\":\"Short name for the job\"},"
            "\"schedule_type\":{\"type\":\"string\",\"description\":\"'every' for recurring interval or 'at' for one-shot at a unix timestamp\"},"
            "\"interval_s\":{\"type\":\"integer\",\"description\":\"Interval in seconds (required for 'every')\"},"
            "\"at_epoch\":{\"type\":\"integer\",\"description\":\"Unix timestamp to fire at (required for 'at')\"},"
            "\"message\":{\"type\":\"string\",\"description\":\"Message to inject when the job fires, triggering an agent turn\"},"
            "\"channel\":{\"type\":\"string\",\"description\":\"Optional reply channel (e.g. 'telegram'). If omitted, current turn channel is used when available\"},"
            "\"chat_id\":{\"type\":\"string\",\"description\":\"Optional reply chat_id. Required when channel='telegram'. If omitted during a Telegram turn, current chat_id is used\"}"
            "},"
            "\"required\":[\"name\",\"schedule_type\",\"message\"]}",
        .execute = tool_cron_add_execute,
    };
    register_tool(&ca);

    /* Register cron_list */
    mimi_tool_t cl = {
        .name = "cron_list",
        .description = "List all scheduled cron jobs with their status, schedule, and IDs.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{},"
            "\"required\":[]}",
        .execute = tool_cron_list_execute,
    };
    register_tool(&cl);

    /* Register cron_remove */
    mimi_tool_t cr = {
        .name = "cron_remove",
        .description = "Remove a scheduled cron job by its ID.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{\"job_id\":{\"type\":\"string\",\"description\":\"The 8-character job ID to remove\"}},"
            "\"required\":[\"job_id\"]}",
        .execute = tool_cron_remove_execute,
    };
    register_tool(&cr);

    /* ── Hardware tools ─────────────────────────────────────── */

    mimi_tool_t gpio_sm = {
        .name = "gpio_set_mode",
        .description = "Configure a GPIO pin as input or output. Modes: 'input', 'output', 'input_pullup', 'input_pulldown'. ESP32-S3 pins 0-25 and 33-48 are available (26-32 reserved for flash).",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"pin\":{\"type\":\"integer\",\"description\":\"GPIO pin number (0-25, 33-48)\"},"
            "\"mode\":{\"type\":\"string\",\"description\":\"Pin mode: input, output, input_pullup, or input_pulldown\"}"
            "},"
            "\"required\":[\"pin\",\"mode\"]}",
        .execute = tool_gpio_set_mode_execute,
    };
    register_tool(&gpio_sm);

    mimi_tool_t gpio_w = {
        .name = "gpio_write",
        .description = "Set a GPIO pin HIGH (1) or LOW (0). The pin should be configured as output first with gpio_set_mode.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"pin\":{\"type\":\"integer\",\"description\":\"GPIO pin number\"},"
            "\"state\":{\"type\":\"integer\",\"description\":\"0 for LOW, 1 for HIGH\"}"
            "},"
            "\"required\":[\"pin\",\"state\"]}",
        .execute = tool_gpio_write_execute,
    };
    register_tool(&gpio_w);

    mimi_tool_t gpio_r = {
        .name = "gpio_read",
        .description = "Read the digital state (HIGH/LOW) of a GPIO pin.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"pin\":{\"type\":\"integer\",\"description\":\"GPIO pin number\"}"
            "},"
            "\"required\":[\"pin\"]}",
        .execute = tool_gpio_read_execute,
    };
    register_tool(&gpio_r);

    mimi_tool_t pwm = {
        .name = "pwm_write",
        .description = "Output a PWM signal on a pin using LEDC. Duty is 0-255 (8-bit). Default frequency is 5000 Hz. Up to 8 simultaneous PWM channels.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"pin\":{\"type\":\"integer\",\"description\":\"GPIO pin number\"},"
            "\"duty\":{\"type\":\"integer\",\"description\":\"PWM duty cycle 0-255 (0=off, 255=fully on)\"},"
            "\"freq_hz\":{\"type\":\"integer\",\"description\":\"PWM frequency in Hz (default 5000)\"}"
            "},"
            "\"required\":[\"pin\",\"duty\"]}",
        .execute = tool_pwm_write_execute,
    };
    register_tool(&pwm);

    mimi_tool_t adc = {
        .name = "adc_read",
        .description = "Read analog voltage from a pin. Returns raw ADC value and approximate voltage. ESP32-S3 ADC1 pins: GPIO 1-10.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"pin\":{\"type\":\"integer\",\"description\":\"ADC-capable GPIO pin (1-10 on ESP32-S3)\"}"
            "},"
            "\"required\":[\"pin\"]}",
        .execute = tool_adc_read_execute,
    };
    register_tool(&adc);

    mimi_tool_t i2c_s = {
        .name = "i2c_scan",
        .description = "Scan an I2C bus for connected devices. Returns a list of detected device addresses. Initializes the I2C bus on the given SDA/SCL pins.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"sda\":{\"type\":\"integer\",\"description\":\"SDA pin number\"},"
            "\"scl\":{\"type\":\"integer\",\"description\":\"SCL pin number\"}"
            "},"
            "\"required\":[\"sda\",\"scl\"]}",
        .execute = tool_i2c_scan_execute,
    };
    register_tool(&i2c_s);

    mimi_tool_t i2c_wr = {
        .name = "i2c_write_read",
        .description = "Write bytes to and/or read bytes from an I2C device. Binary data uses hex encoding (e.g. \"48656C6C6F\"). Provide sda/scl on first use or after pin change; otherwise uses previously configured pins.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"addr\":{\"type\":\"integer\",\"description\":\"7-bit I2C device address (0x08-0x77)\"},"
            "\"write_bytes\":{\"type\":\"string\",\"description\":\"Hex-encoded bytes to write (e.g. \\\"00FF\\\")\"},"
            "\"read_len\":{\"type\":\"integer\",\"description\":\"Number of bytes to read back (0 for write-only)\"},"
            "\"sda\":{\"type\":\"integer\",\"description\":\"SDA pin (optional if already initialized)\"},"
            "\"scl\":{\"type\":\"integer\",\"description\":\"SCL pin (optional if already initialized)\"}"
            "},"
            "\"required\":[\"addr\"]}",
        .execute = tool_i2c_write_read_execute,
    };
    register_tool(&i2c_wr);

    mimi_tool_t spi = {
        .name = "spi_transfer",
        .description = "Full-duplex SPI transfer. Send hex-encoded data and receive the same number of bytes back. Uses SPI2 host at 1 MHz.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"mosi\":{\"type\":\"integer\",\"description\":\"MOSI pin\"},"
            "\"miso\":{\"type\":\"integer\",\"description\":\"MISO pin\"},"
            "\"sclk\":{\"type\":\"integer\",\"description\":\"SCLK pin\"},"
            "\"cs\":{\"type\":\"integer\",\"description\":\"CS (chip select) pin\"},"
            "\"data\":{\"type\":\"string\",\"description\":\"Hex-encoded data to send (e.g. \\\"FF00AB\\\")\"}"
            "},"
            "\"required\":[\"mosi\",\"miso\",\"sclk\",\"cs\",\"data\"]}",
        .execute = tool_spi_transfer_execute,
    };
    register_tool(&spi);

    mimi_tool_t uart_w = {
        .name = "uart_write",
        .description = "Send data over UART port 1 or 2 (port 0 is reserved for serial CLI). Data can be hex-encoded binary or plain text. Initializes the UART with the given pins and baud rate.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"port\":{\"type\":\"integer\",\"description\":\"UART port number (1 or 2)\"},"
            "\"tx\":{\"type\":\"integer\",\"description\":\"TX pin number\"},"
            "\"rx\":{\"type\":\"integer\",\"description\":\"RX pin number\"},"
            "\"baud\":{\"type\":\"integer\",\"description\":\"Baud rate (e.g. 9600, 115200)\"},"
            "\"data\":{\"type\":\"string\",\"description\":\"Data to send (hex string like \\\"48656C6C6F\\\" or plain text)\"}"
            "},"
            "\"required\":[\"port\",\"tx\",\"rx\",\"baud\",\"data\"]}",
        .execute = tool_uart_write_execute,
    };
    register_tool(&uart_w);

    mimi_tool_t uart_r = {
        .name = "uart_read",
        .description = "Read available data from UART port 1 or 2. The port must have been initialized by a prior uart_write call. Returns data in hex and ASCII formats.",
        .input_schema_json =
            "{\"type\":\"object\","
            "\"properties\":{"
            "\"port\":{\"type\":\"integer\",\"description\":\"UART port number (1 or 2)\"},"
            "\"timeout_ms\":{\"type\":\"integer\",\"description\":\"Read timeout in milliseconds (default 1000, max 30000)\"}"
            "},"
            "\"required\":[\"port\"]}",
        .execute = tool_uart_read_execute,
    };
    register_tool(&uart_r);

    build_tools_json();

    ESP_LOGI(TAG, "Tool registry initialized");
    return ESP_OK;
}

const char *tool_registry_get_tools_json(void)
{
    return s_tools_json;
}

esp_err_t tool_registry_execute(const char *name, const char *input_json,
                                char *output, size_t output_size)
{
    for (int i = 0; i < s_tool_count; i++) {
        if (strcmp(s_tools[i].name, name) == 0) {
            ESP_LOGI(TAG, "Executing tool: %s", name);
            return s_tools[i].execute(input_json, output, output_size);
        }
    }

    ESP_LOGW(TAG, "Unknown tool: %s", name);
    snprintf(output, output_size, "Error: unknown tool '%s'", name);
    return ESP_ERR_NOT_FOUND;
}
