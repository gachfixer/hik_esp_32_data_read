#include "tools/tool_hardware.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "esp_log.h"
#include "cJSON.h"
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "driver/i2c.h"
#include "driver/spi_master.h"
#include "driver/uart.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"

static const char *TAG = "tool_hw";

/* ── Pin validation ─────────────────────────────────────────── */

#define GPIO_MAX 48

static bool pin_valid(int pin)
{
    if (pin < 0 || pin > GPIO_MAX) return false;
    /* Reject 26-32: flash/PSRAM on most ESP32-S3 boards */
    if (pin >= 26 && pin <= 32) return false;
    return true;
}

/* ── Hex encoding helpers ───────────────────────────────────── */

static int hex_decode(const char *hex, uint8_t *out, size_t max_out)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t byte_len = hex_len / 2;
    if (byte_len > max_out) return -1;

    for (size_t i = 0; i < byte_len; i++) {
        char hi = hex[i * 2], lo = hex[i * 2 + 1];
        if (!isxdigit((unsigned char)hi) || !isxdigit((unsigned char)lo)) return -1;

        uint8_t val = 0;
        val |= (hi >= 'a' ? hi - 'a' + 10 : hi >= 'A' ? hi - 'A' + 10 : hi - '0') << 4;
        val |= (lo >= 'a' ? lo - 'a' + 10 : lo >= 'A' ? lo - 'A' + 10 : lo - '0');
        out[i] = val;
    }
    return (int)byte_len;
}

static void hex_encode(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 2 < out_size; i++) {
        pos += snprintf(out + pos, out_size - pos, "%02X", data[i]);
    }
    out[pos] = '\0';
}

static void ascii_safe(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 1 < out_size; i++) {
        out[pos++] = (data[i] >= 0x20 && data[i] < 0x7F) ? (char)data[i] : '.';
    }
    out[pos] = '\0';
}

/* ── GPIO tools ─────────────────────────────────────────────── */

esp_err_t tool_gpio_set_mode_execute(const char *input_json, char *output, size_t output_size)
{
    cJSON *root = cJSON_Parse(input_json);
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON input");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *j_pin = cJSON_GetObjectItem(root, "pin");
    cJSON *j_mode = cJSON_GetObjectItem(root, "mode");

    if (!j_pin || !cJSON_IsNumber(j_pin) || !j_mode || !cJSON_IsString(j_mode)) {
        snprintf(output, output_size, "Error: required fields: pin (int), mode (string)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int pin = j_pin->valueint;
    const char *mode = j_mode->valuestring;

    if (!pin_valid(pin)) {
        snprintf(output, output_size, "Error: invalid pin %d (valid: 0-25, 33-48; 26-32 reserved)", pin);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << pin),
        .intr_type = GPIO_INTR_DISABLE,
    };

    if (strcmp(mode, "output") == 0) {
        cfg.mode = GPIO_MODE_OUTPUT;
        cfg.pull_up_en = GPIO_PULLUP_DISABLE;
        cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    } else if (strcmp(mode, "input") == 0) {
        cfg.mode = GPIO_MODE_INPUT;
        cfg.pull_up_en = GPIO_PULLUP_DISABLE;
        cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    } else if (strcmp(mode, "input_pullup") == 0) {
        cfg.mode = GPIO_MODE_INPUT;
        cfg.pull_up_en = GPIO_PULLUP_ENABLE;
        cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    } else if (strcmp(mode, "input_pulldown") == 0) {
        cfg.mode = GPIO_MODE_INPUT;
        cfg.pull_up_en = GPIO_PULLUP_DISABLE;
        cfg.pull_down_en = GPIO_PULLDOWN_ENABLE;
    } else {
        snprintf(output, output_size, "Error: mode must be 'input', 'output', 'input_pullup', or 'input_pulldown'");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = gpio_config(&cfg);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: gpio_config failed: %s", esp_err_to_name(err));
        cJSON_Delete(root);
        return err;
    }

    snprintf(output, output_size, "OK: GPIO %d configured as %s", pin, mode);
    ESP_LOGI(TAG, "gpio_set_mode: pin=%d mode=%s", pin, mode);
    cJSON_Delete(root);
    return ESP_OK;
}

esp_err_t tool_gpio_write_execute(const char *input_json, char *output, size_t output_size)
{
    cJSON *root = cJSON_Parse(input_json);
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON input");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *j_pin = cJSON_GetObjectItem(root, "pin");
    cJSON *j_state = cJSON_GetObjectItem(root, "state");

    if (!j_pin || !cJSON_IsNumber(j_pin) || !j_state || !cJSON_IsNumber(j_state)) {
        snprintf(output, output_size, "Error: required fields: pin (int), state (0 or 1)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int pin = j_pin->valueint;
    int state = j_state->valueint;

    if (!pin_valid(pin)) {
        snprintf(output, output_size, "Error: invalid pin %d (valid: 0-25, 33-48; 26-32 reserved)", pin);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }
    if (state != 0 && state != 1) {
        snprintf(output, output_size, "Error: state must be 0 or 1");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = gpio_set_level((gpio_num_t)pin, state);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: gpio_set_level failed: %s", esp_err_to_name(err));
        cJSON_Delete(root);
        return err;
    }

    snprintf(output, output_size, "OK: GPIO %d set to %s", pin, state ? "HIGH" : "LOW");
    ESP_LOGI(TAG, "gpio_write: pin=%d state=%d", pin, state);
    cJSON_Delete(root);
    return ESP_OK;
}

esp_err_t tool_gpio_read_execute(const char *input_json, char *output, size_t output_size)
{
    cJSON *root = cJSON_Parse(input_json);
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON input");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *j_pin = cJSON_GetObjectItem(root, "pin");
    if (!j_pin || !cJSON_IsNumber(j_pin)) {
        snprintf(output, output_size, "Error: required field: pin (int)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int pin = j_pin->valueint;
    if (!pin_valid(pin)) {
        snprintf(output, output_size, "Error: invalid pin %d (valid: 0-25, 33-48; 26-32 reserved)", pin);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int level = gpio_get_level((gpio_num_t)pin);
    snprintf(output, output_size, "GPIO %d = %d (%s)", pin, level, level ? "HIGH" : "LOW");
    ESP_LOGI(TAG, "gpio_read: pin=%d level=%d", pin, level);
    cJSON_Delete(root);
    return ESP_OK;
}

/* ── PWM (LEDC) ─────────────────────────────────────────────── */

/* Track which LEDC channels are assigned to which pins */
#define LEDC_MAX_CHANNELS 8
static int s_pwm_pin[LEDC_MAX_CHANNELS];
static bool s_pwm_init_done = false;

static void pwm_init_tracking(void)
{
    if (!s_pwm_init_done) {
        for (int i = 0; i < LEDC_MAX_CHANNELS; i++) s_pwm_pin[i] = -1;
        s_pwm_init_done = true;
    }
}

static int pwm_find_or_alloc_channel(int pin)
{
    /* Already assigned? */
    for (int i = 0; i < LEDC_MAX_CHANNELS; i++) {
        if (s_pwm_pin[i] == pin) return i;
    }
    /* Allocate new */
    for (int i = 0; i < LEDC_MAX_CHANNELS; i++) {
        if (s_pwm_pin[i] == -1) {
            s_pwm_pin[i] = pin;
            return i;
        }
    }
    return -1; /* All channels in use */
}

esp_err_t tool_pwm_write_execute(const char *input_json, char *output, size_t output_size)
{
    cJSON *root = cJSON_Parse(input_json);
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON input");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *j_pin = cJSON_GetObjectItem(root, "pin");
    cJSON *j_duty = cJSON_GetObjectItem(root, "duty");
    cJSON *j_freq = cJSON_GetObjectItem(root, "freq_hz");

    if (!j_pin || !cJSON_IsNumber(j_pin) || !j_duty || !cJSON_IsNumber(j_duty)) {
        snprintf(output, output_size, "Error: required fields: pin (int), duty (0-255)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int pin = j_pin->valueint;
    int duty = j_duty->valueint;
    int freq = (j_freq && cJSON_IsNumber(j_freq)) ? j_freq->valueint : 5000;

    if (!pin_valid(pin)) {
        snprintf(output, output_size, "Error: invalid pin %d", pin);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }
    if (duty < 0 || duty > 255) {
        snprintf(output, output_size, "Error: duty must be 0-255");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }
    if (freq < 1 || freq > 40000000) {
        snprintf(output, output_size, "Error: freq_hz must be 1-40000000");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    pwm_init_tracking();
    int ch = pwm_find_or_alloc_channel(pin);
    if (ch < 0) {
        snprintf(output, output_size, "Error: all %d PWM channels in use", LEDC_MAX_CHANNELS);
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }

    ledc_timer_config_t timer_cfg = {
        .speed_mode = LEDC_LOW_SPEED_MODE,
        .timer_num = (ledc_timer_t)(ch / 2),  /* 4 timers, 2 channels each */
        .duty_resolution = LEDC_TIMER_8_BIT,
        .freq_hz = (uint32_t)freq,
        .clk_cfg = LEDC_AUTO_CLK,
    };

    esp_err_t err = ledc_timer_config(&timer_cfg);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: ledc_timer_config failed: %s", esp_err_to_name(err));
        s_pwm_pin[ch] = -1;
        cJSON_Delete(root);
        return err;
    }

    ledc_channel_config_t ch_cfg = {
        .speed_mode = LEDC_LOW_SPEED_MODE,
        .channel = (ledc_channel_t)ch,
        .timer_sel = (ledc_timer_t)(ch / 2),
        .gpio_num = pin,
        .duty = (uint32_t)duty,
        .hpoint = 0,
        .intr_type = LEDC_INTR_DISABLE,
    };

    err = ledc_channel_config(&ch_cfg);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: ledc_channel_config failed: %s", esp_err_to_name(err));
        s_pwm_pin[ch] = -1;
        cJSON_Delete(root);
        return err;
    }

    snprintf(output, output_size, "OK: PWM on GPIO %d, duty=%d/255, freq=%d Hz (channel %d)", pin, duty, freq, ch);
    ESP_LOGI(TAG, "pwm_write: pin=%d duty=%d freq=%d ch=%d", pin, duty, freq, ch);
    cJSON_Delete(root);
    return ESP_OK;
}

/* ── ADC ────────────────────────────────────────────────────── */

/* ESP32-S3 ADC1 channel mapping: GPIO 1-10 → channels 0-9 */
static bool adc_gpio_to_channel(int pin, adc_unit_t *unit, adc_channel_t *channel)
{
    if (pin >= 1 && pin <= 10) {
        *unit = ADC_UNIT_1;
        *channel = (adc_channel_t)(pin - 1);
        return true;
    }
    return false;
}

static adc_oneshot_unit_handle_t s_adc1_handle = NULL;

esp_err_t tool_adc_read_execute(const char *input_json, char *output, size_t output_size)
{
    cJSON *root = cJSON_Parse(input_json);
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON input");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *j_pin = cJSON_GetObjectItem(root, "pin");
    if (!j_pin || !cJSON_IsNumber(j_pin)) {
        snprintf(output, output_size, "Error: required field: pin (int)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int pin = j_pin->valueint;
    adc_unit_t unit;
    adc_channel_t channel;

    if (!adc_gpio_to_channel(pin, &unit, &channel)) {
        snprintf(output, output_size, "Error: GPIO %d is not an ADC pin (valid: 1-10 on ESP32-S3)", pin);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    /* Lazy init ADC1 */
    if (!s_adc1_handle) {
        adc_oneshot_unit_init_cfg_t init_cfg = {
            .unit_id = ADC_UNIT_1,
        };
        esp_err_t err = adc_oneshot_new_unit(&init_cfg, &s_adc1_handle);
        if (err != ESP_OK) {
            snprintf(output, output_size, "Error: ADC init failed: %s", esp_err_to_name(err));
            cJSON_Delete(root);
            return err;
        }
    }

    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    esp_err_t err = adc_oneshot_config_channel(s_adc1_handle, channel, &chan_cfg);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: ADC channel config failed: %s", esp_err_to_name(err));
        cJSON_Delete(root);
        return err;
    }

    int raw = 0;
    err = adc_oneshot_read(s_adc1_handle, channel, &raw);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: ADC read failed: %s", esp_err_to_name(err));
        cJSON_Delete(root);
        return err;
    }

    /* Approximate voltage: 12dB attenuation ≈ 0-3.1V, 12-bit ADC */
    float voltage = (float)raw / 4095.0f * 3.1f;

    snprintf(output, output_size, "GPIO %d ADC: raw=%d, approx=%.2fV (12dB atten, 12-bit)", pin, raw, voltage);
    ESP_LOGI(TAG, "adc_read: pin=%d raw=%d voltage=%.2f", pin, raw, voltage);
    cJSON_Delete(root);
    return ESP_OK;
}

/* ── I2C ────────────────────────────────────────────────────── */

static bool s_i2c_installed = false;
static int  s_i2c_sda = -1;
static int  s_i2c_scl = -1;

static esp_err_t i2c_ensure_init(int sda, int scl, char *output, size_t output_size)
{
    /* Re-init if pins changed */
    if (s_i2c_installed && (s_i2c_sda != sda || s_i2c_scl != scl)) {
        i2c_driver_delete(I2C_NUM_0);
        s_i2c_installed = false;
    }

    if (!s_i2c_installed) {
        i2c_config_t conf = {
            .mode = I2C_MODE_MASTER,
            .sda_io_num = sda,
            .scl_io_num = scl,
            .sda_pullup_en = GPIO_PULLUP_ENABLE,
            .scl_pullup_en = GPIO_PULLUP_ENABLE,
            .master.clk_speed = 100000,
        };
        esp_err_t err = i2c_param_config(I2C_NUM_0, &conf);
        if (err != ESP_OK) {
            snprintf(output, output_size, "Error: i2c_param_config failed: %s", esp_err_to_name(err));
            return err;
        }
        err = i2c_driver_install(I2C_NUM_0, I2C_MODE_MASTER, 0, 0, 0);
        if (err != ESP_OK) {
            snprintf(output, output_size, "Error: i2c_driver_install failed: %s", esp_err_to_name(err));
            return err;
        }
        s_i2c_installed = true;
        s_i2c_sda = sda;
        s_i2c_scl = scl;
        ESP_LOGI(TAG, "I2C initialized: SDA=%d SCL=%d", sda, scl);
    }

    return ESP_OK;
}

esp_err_t tool_i2c_scan_execute(const char *input_json, char *output, size_t output_size)
{
    cJSON *root = cJSON_Parse(input_json);
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON input");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *j_sda = cJSON_GetObjectItem(root, "sda");
    cJSON *j_scl = cJSON_GetObjectItem(root, "scl");

    if (!j_sda || !cJSON_IsNumber(j_sda) || !j_scl || !cJSON_IsNumber(j_scl)) {
        snprintf(output, output_size, "Error: required fields: sda (int), scl (int)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int sda = j_sda->valueint;
    int scl = j_scl->valueint;

    if (!pin_valid(sda) || !pin_valid(scl)) {
        snprintf(output, output_size, "Error: invalid SDA(%d) or SCL(%d) pin", sda, scl);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = i2c_ensure_init(sda, scl, output, output_size);
    if (err != ESP_OK) {
        cJSON_Delete(root);
        return err;
    }

    size_t off = 0;
    off += snprintf(output + off, output_size - off, "I2C scan (SDA=%d, SCL=%d):\n", sda, scl);

    int found = 0;
    for (uint8_t addr = 0x08; addr < 0x78; addr++) {
        i2c_cmd_handle_t cmd = i2c_cmd_link_create();
        i2c_master_start(cmd);
        i2c_master_write_byte(cmd, (addr << 1) | I2C_MASTER_WRITE, true);
        i2c_master_stop(cmd);
        err = i2c_master_cmd_begin(I2C_NUM_0, cmd, pdMS_TO_TICKS(50));
        i2c_cmd_link_delete(cmd);

        if (err == ESP_OK) {
            off += snprintf(output + off, output_size - off, "  0x%02X\n", addr);
            found++;
        }
    }

    if (found == 0) {
        off += snprintf(output + off, output_size - off, "  (no devices found)\n");
    } else {
        off += snprintf(output + off, output_size - off, "Found %d device(s)", found);
    }

    ESP_LOGI(TAG, "i2c_scan: found %d devices", found);
    cJSON_Delete(root);
    return ESP_OK;
}

esp_err_t tool_i2c_write_read_execute(const char *input_json, char *output, size_t output_size)
{
    cJSON *root = cJSON_Parse(input_json);
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON input");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *j_addr = cJSON_GetObjectItem(root, "addr");
    cJSON *j_wb   = cJSON_GetObjectItem(root, "write_bytes");
    cJSON *j_rlen = cJSON_GetObjectItem(root, "read_len");
    cJSON *j_sda  = cJSON_GetObjectItem(root, "sda");
    cJSON *j_scl  = cJSON_GetObjectItem(root, "scl");

    if (!j_addr || !cJSON_IsNumber(j_addr)) {
        snprintf(output, output_size, "Error: required field: addr (int, 7-bit I2C address)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int addr = j_addr->valueint;
    if (addr < 0x08 || addr > 0x77) {
        snprintf(output, output_size, "Error: addr must be 0x08-0x77");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    /* Use stored pins or require them */
    int sda = (j_sda && cJSON_IsNumber(j_sda)) ? j_sda->valueint : s_i2c_sda;
    int scl = (j_scl && cJSON_IsNumber(j_scl)) ? j_scl->valueint : s_i2c_scl;

    if (sda < 0 || scl < 0) {
        snprintf(output, output_size, "Error: I2C not initialized. Provide sda and scl pins, or run i2c_scan first");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = i2c_ensure_init(sda, scl, output, output_size);
    if (err != ESP_OK) {
        cJSON_Delete(root);
        return err;
    }

    /* Decode write bytes */
    uint8_t wbuf[128] = {0};
    int wlen = 0;
    if (j_wb && cJSON_IsString(j_wb) && strlen(j_wb->valuestring) > 0) {
        wlen = hex_decode(j_wb->valuestring, wbuf, sizeof(wbuf));
        if (wlen < 0) {
            snprintf(output, output_size, "Error: write_bytes must be a valid hex string (e.g. \"00FF\")");
            cJSON_Delete(root);
            return ESP_ERR_INVALID_ARG;
        }
    }

    int rlen = (j_rlen && cJSON_IsNumber(j_rlen)) ? j_rlen->valueint : 0;
    if (rlen < 0 || rlen > 128) {
        snprintf(output, output_size, "Error: read_len must be 0-128");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    /* Build I2C transaction */
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();

    if (wlen > 0) {
        i2c_master_start(cmd);
        i2c_master_write_byte(cmd, (addr << 1) | I2C_MASTER_WRITE, true);
        i2c_master_write(cmd, wbuf, wlen, true);
        if (rlen == 0) {
            i2c_master_stop(cmd);
        }
    }

    uint8_t rbuf[128] = {0};
    if (rlen > 0) {
        i2c_master_start(cmd);
        i2c_master_write_byte(cmd, (addr << 1) | I2C_MASTER_READ, true);
        if (rlen > 1) {
            i2c_master_read(cmd, rbuf, rlen - 1, I2C_MASTER_ACK);
        }
        i2c_master_read_byte(cmd, &rbuf[rlen - 1], I2C_MASTER_NACK);
        i2c_master_stop(cmd);
    }

    err = i2c_master_cmd_begin(I2C_NUM_0, cmd, pdMS_TO_TICKS(1000));
    i2c_cmd_link_delete(cmd);

    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: I2C transaction failed: %s", esp_err_to_name(err));
        cJSON_Delete(root);
        return err;
    }

    size_t off = 0;
    off += snprintf(output + off, output_size - off, "OK: I2C addr=0x%02X", addr);
    if (wlen > 0) {
        char hex_str[257];
        hex_encode(wbuf, wlen, hex_str, sizeof(hex_str));
        off += snprintf(output + off, output_size - off, ", wrote %d bytes [%s]", wlen, hex_str);
    }
    if (rlen > 0) {
        char hex_str[257];
        char asc_str[129];
        hex_encode(rbuf, rlen, hex_str, sizeof(hex_str));
        ascii_safe(rbuf, rlen, asc_str, sizeof(asc_str));
        off += snprintf(output + off, output_size - off, ", read %d bytes: hex=[%s] ascii=[%s]", rlen, hex_str, asc_str);
    }

    ESP_LOGI(TAG, "i2c_write_read: addr=0x%02X wrote=%d read=%d", addr, wlen, rlen);
    cJSON_Delete(root);
    return ESP_OK;
}

/* ── SPI ────────────────────────────────────────────────────── */

static spi_device_handle_t s_spi_handle = NULL;
static int s_spi_mosi = -1, s_spi_miso = -1, s_spi_sclk = -1, s_spi_cs = -1;

static esp_err_t spi_ensure_init(int mosi, int miso, int sclk, int cs, char *output, size_t output_size)
{
    /* Re-init if pins changed */
    if (s_spi_handle &&
        (s_spi_mosi != mosi || s_spi_miso != miso || s_spi_sclk != sclk || s_spi_cs != cs)) {
        spi_bus_remove_device(s_spi_handle);
        spi_bus_free(SPI2_HOST);
        s_spi_handle = NULL;
    }

    if (!s_spi_handle) {
        spi_bus_config_t bus_cfg = {
            .mosi_io_num = mosi,
            .miso_io_num = miso,
            .sclk_io_num = sclk,
            .quadwp_io_num = -1,
            .quadhd_io_num = -1,
            .max_transfer_sz = 256,
        };
        esp_err_t err = spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
        if (err != ESP_OK) {
            snprintf(output, output_size, "Error: spi_bus_initialize failed: %s", esp_err_to_name(err));
            return err;
        }

        spi_device_interface_config_t dev_cfg = {
            .clock_speed_hz = 1000000,  /* 1 MHz default */
            .mode = 0,
            .spics_io_num = cs,
            .queue_size = 1,
        };
        err = spi_bus_add_device(SPI2_HOST, &dev_cfg, &s_spi_handle);
        if (err != ESP_OK) {
            spi_bus_free(SPI2_HOST);
            snprintf(output, output_size, "Error: spi_bus_add_device failed: %s", esp_err_to_name(err));
            return err;
        }

        s_spi_mosi = mosi;
        s_spi_miso = miso;
        s_spi_sclk = sclk;
        s_spi_cs = cs;
        ESP_LOGI(TAG, "SPI initialized: MOSI=%d MISO=%d SCLK=%d CS=%d", mosi, miso, sclk, cs);
    }

    return ESP_OK;
}

esp_err_t tool_spi_transfer_execute(const char *input_json, char *output, size_t output_size)
{
    cJSON *root = cJSON_Parse(input_json);
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON input");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *j_mosi = cJSON_GetObjectItem(root, "mosi");
    cJSON *j_miso = cJSON_GetObjectItem(root, "miso");
    cJSON *j_sclk = cJSON_GetObjectItem(root, "sclk");
    cJSON *j_cs   = cJSON_GetObjectItem(root, "cs");
    cJSON *j_data = cJSON_GetObjectItem(root, "data");

    if (!j_mosi || !cJSON_IsNumber(j_mosi) ||
        !j_miso || !cJSON_IsNumber(j_miso) ||
        !j_sclk || !cJSON_IsNumber(j_sclk) ||
        !j_cs   || !cJSON_IsNumber(j_cs)   ||
        !j_data || !cJSON_IsString(j_data)) {
        snprintf(output, output_size, "Error: required fields: mosi, miso, sclk, cs (int), data (hex string)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int mosi = j_mosi->valueint;
    int miso = j_miso->valueint;
    int sclk = j_sclk->valueint;
    int cs   = j_cs->valueint;

    if (!pin_valid(mosi) || !pin_valid(miso) || !pin_valid(sclk) || !pin_valid(cs)) {
        snprintf(output, output_size, "Error: invalid pin(s)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t tx_buf[128];
    int data_len = hex_decode(j_data->valuestring, tx_buf, sizeof(tx_buf));
    if (data_len <= 0) {
        snprintf(output, output_size, "Error: data must be a non-empty valid hex string");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = spi_ensure_init(mosi, miso, sclk, cs, output, output_size);
    if (err != ESP_OK) {
        cJSON_Delete(root);
        return err;
    }

    uint8_t rx_buf[128] = {0};
    spi_transaction_t txn = {
        .length = data_len * 8,
        .tx_buffer = tx_buf,
        .rx_buffer = rx_buf,
    };

    err = spi_device_transmit(s_spi_handle, &txn);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: SPI transfer failed: %s", esp_err_to_name(err));
        cJSON_Delete(root);
        return err;
    }

    char tx_hex[257], rx_hex[257], rx_asc[129];
    hex_encode(tx_buf, data_len, tx_hex, sizeof(tx_hex));
    hex_encode(rx_buf, data_len, rx_hex, sizeof(rx_hex));
    ascii_safe(rx_buf, data_len, rx_asc, sizeof(rx_asc));

    snprintf(output, output_size,
             "OK: SPI %d bytes transferred\n  TX: [%s]\n  RX: hex=[%s] ascii=[%s]",
             data_len, tx_hex, rx_hex, rx_asc);

    ESP_LOGI(TAG, "spi_transfer: %d bytes", data_len);
    cJSON_Delete(root);
    return ESP_OK;
}

/* ── UART ───────────────────────────────────────────────────── */

#define UART_BUF_SIZE 256

typedef struct {
    bool installed;
    int  tx_pin;
    int  rx_pin;
    int  baud;
} uart_state_t;

static uart_state_t s_uart[3] = {0};  /* index 0 unused, ports 1 and 2 */

static esp_err_t uart_ensure_init(int port, int tx, int rx, int baud, char *output, size_t output_size)
{
    uart_state_t *st = &s_uart[port];

    /* Re-init if config changed */
    if (st->installed && (st->tx_pin != tx || st->rx_pin != rx || st->baud != baud)) {
        uart_driver_delete(port);
        st->installed = false;
    }

    if (!st->installed) {
        uart_config_t cfg = {
            .baud_rate = baud,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .source_clk = UART_SCLK_DEFAULT,
        };
        esp_err_t err = uart_param_config(port, &cfg);
        if (err != ESP_OK) {
            snprintf(output, output_size, "Error: uart_param_config failed: %s", esp_err_to_name(err));
            return err;
        }

        err = uart_set_pin(port, tx, rx, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
        if (err != ESP_OK) {
            snprintf(output, output_size, "Error: uart_set_pin failed: %s", esp_err_to_name(err));
            return err;
        }

        err = uart_driver_install(port, UART_BUF_SIZE * 2, UART_BUF_SIZE * 2, 0, NULL, 0);
        if (err != ESP_OK) {
            snprintf(output, output_size, "Error: uart_driver_install failed: %s", esp_err_to_name(err));
            return err;
        }

        st->installed = true;
        st->tx_pin = tx;
        st->rx_pin = rx;
        st->baud = baud;
        ESP_LOGI(TAG, "UART%d initialized: TX=%d RX=%d baud=%d", port, tx, rx, baud);
    }

    return ESP_OK;
}

esp_err_t tool_uart_write_execute(const char *input_json, char *output, size_t output_size)
{
    cJSON *root = cJSON_Parse(input_json);
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON input");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *j_port = cJSON_GetObjectItem(root, "port");
    cJSON *j_tx   = cJSON_GetObjectItem(root, "tx");
    cJSON *j_rx   = cJSON_GetObjectItem(root, "rx");
    cJSON *j_baud = cJSON_GetObjectItem(root, "baud");
    cJSON *j_data = cJSON_GetObjectItem(root, "data");

    if (!j_port || !cJSON_IsNumber(j_port) ||
        !j_tx   || !cJSON_IsNumber(j_tx)   ||
        !j_rx   || !cJSON_IsNumber(j_rx)   ||
        !j_baud || !cJSON_IsNumber(j_baud) ||
        !j_data || !cJSON_IsString(j_data)) {
        snprintf(output, output_size, "Error: required fields: port (1 or 2), tx, rx, baud (int), data (string)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int port = j_port->valueint;
    int tx   = j_tx->valueint;
    int rx   = j_rx->valueint;
    int baud = j_baud->valueint;
    const char *data = j_data->valuestring;

    if (port != 1 && port != 2) {
        snprintf(output, output_size, "Error: port must be 1 or 2 (port 0 is reserved for CLI)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }
    if (!pin_valid(tx) || !pin_valid(rx)) {
        snprintf(output, output_size, "Error: invalid TX(%d) or RX(%d) pin", tx, rx);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = uart_ensure_init(port, tx, rx, baud, output, output_size);
    if (err != ESP_OK) {
        cJSON_Delete(root);
        return err;
    }

    /* Try hex decode first; if it fails, send as raw text */
    uint8_t bin_buf[128];
    int bin_len = hex_decode(data, bin_buf, sizeof(bin_buf));

    int sent;
    if (bin_len > 0) {
        sent = uart_write_bytes(port, (const char *)bin_buf, bin_len);
    } else {
        sent = uart_write_bytes(port, data, strlen(data));
    }

    if (sent < 0) {
        snprintf(output, output_size, "Error: uart_write_bytes failed");
        cJSON_Delete(root);
        return ESP_FAIL;
    }

    snprintf(output, output_size, "OK: UART%d sent %d bytes (TX=%d, baud=%d)", port, sent, tx, baud);
    ESP_LOGI(TAG, "uart_write: port=%d sent=%d", port, sent);
    cJSON_Delete(root);
    return ESP_OK;
}

esp_err_t tool_uart_read_execute(const char *input_json, char *output, size_t output_size)
{
    cJSON *root = cJSON_Parse(input_json);
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON input");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *j_port    = cJSON_GetObjectItem(root, "port");
    cJSON *j_timeout = cJSON_GetObjectItem(root, "timeout_ms");

    if (!j_port || !cJSON_IsNumber(j_port)) {
        snprintf(output, output_size, "Error: required field: port (1 or 2)");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    int port = j_port->valueint;
    int timeout_ms = (j_timeout && cJSON_IsNumber(j_timeout)) ? j_timeout->valueint : 1000;

    if (port != 1 && port != 2) {
        snprintf(output, output_size, "Error: port must be 1 or 2");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    if (!s_uart[port].installed) {
        snprintf(output, output_size, "Error: UART%d not initialized. Use uart_write first to configure pins and baud", port);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_STATE;
    }

    if (timeout_ms < 0 || timeout_ms > 30000) {
        timeout_ms = 1000;
    }

    uint8_t buf[UART_BUF_SIZE];
    int len = uart_read_bytes(port, buf, sizeof(buf) - 1, pdMS_TO_TICKS(timeout_ms));

    if (len <= 0) {
        snprintf(output, output_size, "UART%d: no data received (timeout=%dms)", port, timeout_ms);
        cJSON_Delete(root);
        return ESP_OK;
    }

    char hex_str[UART_BUF_SIZE * 2 + 1];
    char asc_str[UART_BUF_SIZE + 1];
    hex_encode(buf, len, hex_str, sizeof(hex_str));
    ascii_safe(buf, len, asc_str, sizeof(asc_str));

    snprintf(output, output_size,
             "UART%d read %d bytes:\n  hex=[%s]\n  ascii=[%s]",
             port, len, hex_str, asc_str);

    ESP_LOGI(TAG, "uart_read: port=%d len=%d", port, len);
    cJSON_Delete(root);
    return ESP_OK;
}
