#include "serial_cli.h"
#include "mimi_config.h"
#include "wifi/wifi_manager.h"
#include "telegram/telegram_bot.h"
#include "llm/llm_proxy.h"
#include "memory/memory_store.h"
#include "memory/session_mgr.h"
#include "proxy/http_proxy.h"
#include "tools/tool_registry.h"
#include "tools/tool_web_search.h"
#include "cron/cron_service.h"
#include "heartbeat/heartbeat.h"
#include "skills/skill_loader.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <dirent.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/uart.h"

static const char *TAG = "cli";

/* ── Line buffer ────────────────────────────────────────────────── */

#define CLI_LINE_MAX  256
#define CLI_MAX_ARGS  16

static char s_line[CLI_LINE_MAX];
static int  s_line_pos = 0;

/* ── argv parser ────────────────────────────────────────────────── */

static int parse_argv(char *line, char *argv[], int max_args)
{
    int argc = 0;
    char *p = line;

    while (*p && argc < max_args) {
        /* skip whitespace */
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        argv[argc++] = p;

        /* advance to next whitespace */
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p) *p++ = '\0';
    }
    return argc;
}

/* ── Command handlers ───────────────────────────────────────────── */

static int cmd_help(int argc, char **argv);

static int cmd_wifi_set(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: set_wifi <ssid> <password>\n");
        return 1;
    }
    wifi_manager_set_credentials(argv[1], argv[2]);
    printf("WiFi credentials saved. Restart to apply.\n");
    return 0;
}

static int cmd_wifi_status(int argc, char **argv)
{
    printf("WiFi connected: %s\n", wifi_manager_is_connected() ? "yes" : "no");
    printf("IP: %s\n", wifi_manager_get_ip());
    return 0;
}

static int cmd_wifi_scan(int argc, char **argv)
{
    wifi_manager_scan_and_print();
    return 0;
}

static int cmd_set_tg_token(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: set_tg_token <token>\n");
        return 1;
    }
    telegram_set_token(argv[1]);
    printf("Telegram bot token saved.\n");
    return 0;
}

static int cmd_set_api_key(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: set_api_key <key>\n");
        return 1;
    }
    llm_set_api_key(argv[1]);
    printf("API key saved.\n");
    return 0;
}

static int cmd_set_model(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: set_model <model>\n");
        return 1;
    }
    llm_set_model(argv[1]);
    printf("Model set.\n");
    return 0;
}

static int cmd_set_model_provider(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: set_model_provider <provider>\n");
        return 1;
    }
    llm_set_provider(argv[1]);
    printf("Model provider set.\n");
    return 0;
}

static int cmd_memory_read(int argc, char **argv)
{
    char *buf = malloc(4096);
    if (!buf) {
        printf("Out of memory.\n");
        return 1;
    }
    if (memory_read_long_term(buf, 4096) == ESP_OK && buf[0]) {
        printf("=== MEMORY.md ===\n%s\n=================\n", buf);
    } else {
        printf("MEMORY.md is empty or not found.\n");
    }
    free(buf);
    return 0;
}

static int cmd_memory_write(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: memory_write <content>\n");
        return 1;
    }
    memory_write_long_term(argv[1]);
    printf("MEMORY.md updated.\n");
    return 0;
}

static int cmd_session_list(int argc, char **argv)
{
    printf("Sessions:\n");
    session_list();
    return 0;
}

static int cmd_session_clear(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: session_clear <chat_id>\n");
        return 1;
    }
    if (session_clear(argv[1]) == ESP_OK) {
        printf("Session cleared.\n");
    } else {
        printf("Session not found.\n");
    }
    return 0;
}

static int cmd_heap_info(int argc, char **argv)
{
    printf("Internal free: %d bytes\n",
           (int)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    printf("PSRAM free:    %d bytes\n",
           (int)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    printf("Total free:    %d bytes\n",
           (int)esp_get_free_heap_size());
    return 0;
}

static int cmd_set_proxy(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: set_proxy <host> <port> [http|socks5]\n");
        return 1;
    }
    const char *proxy_type = "http";
    if (argc >= 4 && argv[3][0]) {
        proxy_type = argv[3];
    }
    if (strcmp(proxy_type, "http") != 0 && strcmp(proxy_type, "socks5") != 0) {
        printf("Invalid proxy type: %s. Use http or socks5.\n", proxy_type);
        return 1;
    }
    int port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        printf("Invalid port: %s\n", argv[2]);
        return 1;
    }
    http_proxy_set(argv[1], (uint16_t)port, proxy_type);
    printf("Proxy set. Restart to apply.\n");
    return 0;
}

static int cmd_clear_proxy(int argc, char **argv)
{
    http_proxy_clear();
    printf("Proxy cleared. Restart to apply.\n");
    return 0;
}

static int cmd_set_search_key(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: set_search_key <key>\n");
        return 1;
    }
    tool_web_search_set_key(argv[1]);
    printf("Search API key saved.\n");
    return 0;
}

static int cmd_skill_list(int argc, char **argv)
{
    char *buf = malloc(4096);
    if (!buf) {
        printf("Out of memory.\n");
        return 1;
    }

    size_t n = skill_loader_build_summary(buf, 4096);
    if (n == 0) {
        printf("No skills found under " MIMI_SKILLS_PREFIX ".\n");
    } else {
        printf("=== Skills ===\n%s", buf);
    }
    free(buf);
    return 0;
}

static bool has_md_suffix(const char *name)
{
    size_t len = strlen(name);
    return (len >= 3) && strcmp(name + len - 3, ".md") == 0;
}

static bool build_skill_path(const char *name, char *out, size_t out_size)
{
    if (!name || !name[0]) return false;
    if (strstr(name, "..") != NULL) return false;
    if (strchr(name, '/') != NULL || strchr(name, '\\') != NULL) return false;

    if (has_md_suffix(name)) {
        snprintf(out, out_size, MIMI_SKILLS_PREFIX "%s", name);
    } else {
        snprintf(out, out_size, MIMI_SKILLS_PREFIX "%s.md", name);
    }
    return true;
}

static int cmd_skill_show(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: skill_show <name>\n");
        return 1;
    }

    char path[128];
    if (!build_skill_path(argv[1], path, sizeof(path))) {
        printf("Invalid skill name.\n");
        return 1;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        printf("Skill not found: %s\n", path);
        return 1;
    }

    printf("=== %s ===\n", path);
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        fputs(line, stdout);
    }
    fclose(f);
    printf("\n============\n");
    return 0;
}

static bool contains_nocase(const char *text, const char *keyword)
{
    if (!text || !keyword || !keyword[0]) return false;

    size_t key_len = strlen(keyword);
    for (const char *p = text; *p; p++) {
        size_t i = 0;
        while (i < key_len && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)keyword[i])) {
            i++;
        }
        if (i == key_len) return true;
    }
    return false;
}

static int cmd_skill_search(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: skill_search <keyword>\n");
        return 1;
    }

    const char *keyword = argv[1];
    DIR *dir = opendir(MIMI_SPIFFS_BASE);
    if (!dir) {
        printf("Cannot open " MIMI_SPIFFS_BASE ".\n");
        return 1;
    }

    const char *prefix = "skills/";
    const size_t prefix_len = strlen(prefix);
    int matches = 0;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        size_t name_len = strlen(name);

        if (strncmp(name, prefix, prefix_len) != 0) continue;
        if (name_len < prefix_len + 4) continue;
        if (strcmp(name + name_len - 3, ".md") != 0) continue;

        char full_path[296];
        snprintf(full_path, sizeof(full_path), MIMI_SPIFFS_BASE "/%s", name);

        bool file_matched = contains_nocase(name, keyword);
        int matched_line = 0;

        FILE *f = fopen(full_path, "r");
        if (!f) continue;

        char line[256];
        int line_no = 0;
        while (!file_matched && fgets(line, sizeof(line), f)) {
            line_no++;
            if (contains_nocase(line, keyword)) {
                file_matched = true;
                matched_line = line_no;
            }
        }
        fclose(f);

        if (file_matched) {
            matches++;
            if (matched_line > 0) {
                printf("- %s (matched at line %d)\n", full_path, matched_line);
            } else {
                printf("- %s (matched in filename)\n", full_path);
            }
        }
    }

    closedir(dir);
    if (matches == 0) {
        printf("No skills matched keyword: %s\n", keyword);
    } else {
        printf("Total matches: %d\n", matches);
    }
    return 0;
}

static void print_config(const char *label, const char *ns, const char *key,
                         const char *build_val, bool mask)
{
    char nvs_val[128] = {0};
    const char *source = "not set";
    const char *display = "(empty)";

    /* NVS takes highest priority */
    nvs_handle_t nvs;
    if (nvs_open(ns, NVS_READONLY, &nvs) == ESP_OK) {
        size_t len = sizeof(nvs_val);
        if (nvs_get_str(nvs, key, nvs_val, &len) == ESP_OK && nvs_val[0]) {
            source = "NVS";
            display = nvs_val;
        }
        nvs_close(nvs);
    }

    /* Fall back to build-time value */
    if (strcmp(source, "not set") == 0 && build_val[0] != '\0') {
        source = "build";
        display = build_val;
    }

    if (mask && strlen(display) > 6 && strcmp(display, "(empty)") != 0) {
        printf("  %-14s: %.4s****  [%s]\n", label, display, source);
    } else {
        printf("  %-14s: %s  [%s]\n", label, display, source);
    }
}

static int cmd_config_show(int argc, char **argv)
{
    printf("=== Current Configuration ===\n");
    print_config("WiFi SSID",  MIMI_NVS_WIFI,   MIMI_NVS_KEY_SSID,     MIMI_SECRET_WIFI_SSID,  false);
    print_config("WiFi Pass",  MIMI_NVS_WIFI,   MIMI_NVS_KEY_PASS,     MIMI_SECRET_WIFI_PASS,  true);
    print_config("TG Token",   MIMI_NVS_TG,     MIMI_NVS_KEY_TG_TOKEN, MIMI_SECRET_TG_TOKEN,   true);
    print_config("API Key",    MIMI_NVS_LLM,    MIMI_NVS_KEY_API_KEY,  MIMI_SECRET_API_KEY,    true);
    print_config("Model",      MIMI_NVS_LLM,    MIMI_NVS_KEY_MODEL,    MIMI_SECRET_MODEL,      false);
    print_config("Provider",   MIMI_NVS_LLM,    MIMI_NVS_KEY_PROVIDER, MIMI_SECRET_MODEL_PROVIDER, false);
    print_config("Proxy Host", MIMI_NVS_PROXY,  MIMI_NVS_KEY_PROXY_HOST, MIMI_SECRET_PROXY_HOST, false);
    print_config("Proxy Port", MIMI_NVS_PROXY,  MIMI_NVS_KEY_PROXY_PORT, MIMI_SECRET_PROXY_PORT, false);
    print_config("Search Key", MIMI_NVS_SEARCH, MIMI_NVS_KEY_API_KEY,  MIMI_SECRET_SEARCH_KEY, true);
    printf("=============================\n");
    return 0;
}

static int cmd_config_reset(int argc, char **argv)
{
    const char *namespaces[] = {
        MIMI_NVS_WIFI, MIMI_NVS_TG, MIMI_NVS_LLM, MIMI_NVS_PROXY, MIMI_NVS_SEARCH
    };
    for (int i = 0; i < 5; i++) {
        nvs_handle_t nvs;
        if (nvs_open(namespaces[i], NVS_READWRITE, &nvs) == ESP_OK) {
            nvs_erase_all(nvs);
            nvs_commit(nvs);
            nvs_close(nvs);
        }
    }
    printf("All NVS config cleared. Build-time defaults will be used on restart.\n");
    return 0;
}

static int cmd_heartbeat_trigger(int argc, char **argv)
{
    printf("Checking HEARTBEAT.md...\n");
    if (heartbeat_trigger()) {
        printf("Heartbeat: agent prompted with pending tasks.\n");
    } else {
        printf("Heartbeat: no actionable tasks found.\n");
    }
    return 0;
}

static int cmd_cron_start(int argc, char **argv)
{
    esp_err_t err = cron_service_start();
    if (err == ESP_OK) {
        printf("Cron service started.\n");
        return 0;
    }

    printf("Failed to start cron service: %s\n", esp_err_to_name(err));
    return 1;
}

static int cmd_tool_exec(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: tool_exec <name> [json]\n");
        return 1;
    }

    const char *tool_name = argv[1];
    const char *input_json = (argc >= 3) ? argv[2] : "{}";

    char *output = calloc(1, 4096);
    if (!output) {
        printf("Out of memory.\n");
        return 1;
    }

    esp_err_t err = tool_registry_execute(tool_name, input_json, output, 4096);
    printf("tool_exec status: %s\n", esp_err_to_name(err));
    printf("%s\n", output[0] ? output : "(empty)");
    free(output);
    return (err == ESP_OK) ? 0 : 1;
}

static int cmd_restart(int argc, char **argv)
{
    printf("Restarting...\n");
    esp_restart();
    return 0;  /* unreachable */
}

/* ── Command dispatch table ─────────────────────────────────────── */

typedef int (*cli_handler_t)(int argc, char **argv);

typedef struct {
    const char *name;
    const char *help;
    cli_handler_t handler;
} cli_cmd_t;

static const cli_cmd_t s_commands[] = {
    { "help",              "Show available commands",                            cmd_help },
    { "set_wifi",          "Set WiFi SSID and password (set_wifi <ssid> <pass>)",cmd_wifi_set },
    { "wifi_status",       "Show WiFi connection status",                       cmd_wifi_status },
    { "wifi_scan",         "Scan and list nearby WiFi APs",                     cmd_wifi_scan },
    { "set_tg_token",      "Set Telegram bot token",                            cmd_set_tg_token },
    { "set_api_key",       "Set LLM API key",                                   cmd_set_api_key },
    { "set_model",         "Set LLM model (default: " MIMI_LLM_DEFAULT_MODEL ")", cmd_set_model },
    { "set_model_provider","Set LLM model provider (default: " MIMI_LLM_PROVIDER_DEFAULT ")", cmd_set_model_provider },
    { "skill_list",        "List installed skills",                              cmd_skill_list },
    { "skill_show",        "Print a skill file (skill_show <name>)",             cmd_skill_show },
    { "skill_search",      "Search skills by keyword (skill_search <keyword>)",  cmd_skill_search },
    { "memory_read",       "Read MEMORY.md",                                     cmd_memory_read },
    { "memory_write",      "Write to MEMORY.md (memory_write <content>)",        cmd_memory_write },
    { "session_list",      "List all sessions",                                  cmd_session_list },
    { "session_clear",     "Clear a session (session_clear <chat_id>)",          cmd_session_clear },
    { "heap_info",         "Show heap memory usage",                             cmd_heap_info },
    { "set_search_key",    "Set Brave Search API key",                           cmd_set_search_key },
    { "set_proxy",         "Set proxy (set_proxy <host> <port> [http|socks5])",  cmd_set_proxy },
    { "clear_proxy",       "Remove proxy configuration",                         cmd_clear_proxy },
    { "config_show",       "Show current configuration (build-time + NVS)",      cmd_config_show },
    { "config_reset",      "Clear all NVS overrides",                            cmd_config_reset },
    { "heartbeat_trigger", "Manually trigger a heartbeat check",                 cmd_heartbeat_trigger },
    { "cron_start",        "Start cron scheduler timer now",                     cmd_cron_start },
    { "tool_exec",         "Execute a tool: tool_exec <name> [json]",            cmd_tool_exec },
    { "restart",           "Restart the device",                                 cmd_restart },
};

#define NUM_COMMANDS (sizeof(s_commands) / sizeof(s_commands[0]))

static int cmd_help(int argc, char **argv)
{
    printf("Available commands:\n");
    for (int i = 0; i < (int)NUM_COMMANDS; i++) {
        printf("  %-20s %s\n", s_commands[i].name, s_commands[i].help);
    }
    return 0;
}

/* ── Dispatch ───────────────────────────────────────────────────── */

static void dispatch_line(char *line)
{
    char *argv[CLI_MAX_ARGS];
    int argc = parse_argv(line, argv, CLI_MAX_ARGS);
    if (argc == 0) return;

    for (int i = 0; i < (int)NUM_COMMANDS; i++) {
        if (strcmp(argv[0], s_commands[i].name) == 0) {
            s_commands[i].handler(argc, argv);
            return;
        }
    }

    printf("Unknown command: %s. Type 'help' for available commands.\n", argv[0]);
}

/* ── Public API ─────────────────────────────────────────────────── */

esp_err_t serial_cli_init(void)
{
    /* Configure UART0 for CLI input */
    uart_config_t uart_cfg = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    /* Only install driver if not already installed (Arduino may have done it) */
    if (!uart_is_driver_installed(UART_NUM_0)) {
        ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 256, 0, 0, NULL, 0));
        ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_cfg));
    }

    s_line_pos = 0;
    printf("mimi> ");
    fflush(stdout);

    ESP_LOGI(TAG, "Serial CLI started (polling mode)");
    return ESP_OK;
}

void serial_cli_poll(void)
{
    uint8_t ch;
    int len = uart_read_bytes(UART_NUM_0, &ch, 1, 0);
    if (len <= 0) return;

    /* Handle backspace */
    if (ch == '\b' || ch == 0x7F) {
        if (s_line_pos > 0) {
            s_line_pos--;
            printf("\b \b");
            fflush(stdout);
        }
        return;
    }

    /* Handle newline */
    if (ch == '\n' || ch == '\r') {
        printf("\n");
        s_line[s_line_pos] = '\0';

        if (s_line_pos > 0) {
            dispatch_line(s_line);
        }

        s_line_pos = 0;
        printf("mimi> ");
        fflush(stdout);
        return;
    }

    /* Buffer printable characters */
    if (s_line_pos < CLI_LINE_MAX - 1 && ch >= 0x20) {
        s_line[s_line_pos++] = (char)ch;
        /* Echo */
        putchar(ch);
        fflush(stdout);
    }
}
