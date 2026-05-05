/*
 * MimiClawBasic - Minimal Arduino sketch for MimiClaw AI Agent
 *
 * Hardware: ESP32-S3 with 16MB flash + 8MB PSRAM
 *
 * Setup:
 *   1. Edit mimi_secrets.h (next to this .ino) with your credentials
 *   2. Upload SPIFFS data (PlatformIO: pio run -t uploadfs)
 *   3. Build and flash
 *   4. Open serial monitor at 115200 baud
 *   5. Type 'help' for available CLI commands
 */

#include <MimiClaw.h>

MimiClaw mimi;

void setup() {
    /* MimiClaw handles its own serial/UART setup */
    mimi.begin();
    mimi.start();
}

void loop() {
    mimi.loop();
}
