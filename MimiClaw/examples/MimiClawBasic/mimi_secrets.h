/*
 * MimiClaw Secrets - Fill in your credentials below.
 *
 * This file lives next to your .ino sketch.
 * The library picks it up automatically at compile time.
 */

#pragma once

/* WiFi */
#define MIMI_SECRET_WIFI_SSID       "your-wifi-ssid"
#define MIMI_SECRET_WIFI_PASS       "your-wifi-password"

/* Telegram Bot (get from @BotFather) */
#define MIMI_SECRET_TG_TOKEN        ""

/* LLM API */
#define MIMI_SECRET_API_KEY         ""
#define MIMI_SECRET_MODEL           ""
#define MIMI_SECRET_MODEL_PROVIDER  "anthropic"   /* "anthropic" or "openai" */

/* HTTP Proxy (optional - leave empty to disable) */
#define MIMI_SECRET_PROXY_HOST      ""
#define MIMI_SECRET_PROXY_PORT      ""
#define MIMI_SECRET_PROXY_TYPE      ""            /* "http" or "socks5" */

/* Brave Search API (optional) */
#define MIMI_SECRET_SEARCH_KEY      ""
