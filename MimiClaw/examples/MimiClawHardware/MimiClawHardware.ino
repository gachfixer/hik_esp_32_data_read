/*
 * MimiClawHardware - AI Agent with Hardware Control
 *
 * This example is identical to MimiClawBasic — all 10 hardware tools
 * (GPIO, PWM, ADC, I2C, SPI, UART) are built into the MimiClaw library.
 * Simply wire up your peripherals, flash this sketch, and tell the agent
 * what to do via Telegram or serial.
 *
 * Hardware: ESP32-S3 with 16MB flash + 8MB PSRAM
 *
 * ┌──────────────────────────────────────────────────────────────┐
 * │  EXAMPLE WIRING                                              │
 * ├──────────────────────────────────────────────────────────────┤
 * │                                                              │
 * │  LED (output)                                                │
 * │    GPIO 2  ──►  220Ω  ──►  LED  ──►  GND                    │
 * │                                                              │
 * │  Button (input with pull-up)                                 │
 * │    GPIO 4  ──►  Button  ──►  GND                             │
 * │    (use gpio_set_mode pin=4 mode=input_pullup)               │
 * │                                                              │
 * │  I2C sensor (e.g. TMP102, BMP280, SHT30)                    │
 * │    GPIO 8  ──►  SDA                                          │
 * │    GPIO 9  ──►  SCL                                          │
 * │    3.3V    ──►  VCC                                          │
 * │    GND     ──►  GND                                          │
 * │                                                              │
 * │  SPI device (e.g. SD card, display, LoRa)                   │
 * │    GPIO 11 ──►  MOSI                                         │
 * │    GPIO 13 ──►  MISO                                         │
 * │    GPIO 12 ──►  SCLK                                         │
 * │    GPIO 10 ──►  CS                                           │
 * │                                                              │
 * │  UART device (e.g. GPS, RS485, fingerprint)                  │
 * │    GPIO 17 ──►  TX  (connect to device RX)                   │
 * │    GPIO 18 ──►  RX  (connect to device TX)                   │
 * │                                                              │
 * │  Analog sensor (e.g. potentiometer, LDR, thermistor)         │
 * │    GPIO 1  ──►  Sensor signal (ADC1, 0-3.1V)                │
 * │                                                              │
 * │  PWM output (e.g. servo, buzzer, LED dimming)                │
 * │    GPIO 2  ──►  Signal pin                                   │
 * │                                                              │
 * └──────────────────────────────────────────────────────────────┘
 *
 * WHAT TO ASK THE AGENT:
 *
 *   "Turn on the LED on pin 2"
 *     → gpio_set_mode(pin=2, mode=output)
 *     → gpio_write(pin=2, state=1)
 *
 *   "Is the button on pin 4 pressed?"
 *     → gpio_set_mode(pin=4, mode=input_pullup)
 *     → gpio_read(pin=4)   // 0 = pressed, 1 = released
 *
 *   "Dim the LED on pin 2 to 50%"
 *     → pwm_write(pin=2, duty=128)
 *
 *   "Read the analog sensor on pin 1"
 *     → adc_read(pin=1)
 *
 *   "Scan for I2C devices on SDA=8 SCL=9"
 *     → i2c_scan(sda=8, scl=9)
 *
 *   "Read 2 bytes from I2C device 0x48 register 0x00"
 *     → i2c_write_read(addr=0x48, write_bytes="00", read_len=2)
 *
 *   "Send 'Hello' over UART2 at 9600 baud on TX=17 RX=18"
 *     → uart_write(port=2, tx=17, rx=18, baud=9600, data="48656C6C6F")
 *
 *   "Read from UART2"
 *     → uart_read(port=2, timeout_ms=2000)
 *
 *   "Send SPI data FF00 on MOSI=11 MISO=13 SCLK=12 CS=10"
 *     → spi_transfer(mosi=11, miso=13, sclk=12, cs=10, data="FF00")
 *
 * NOTES:
 *   - Pins 26-32 are reserved (flash/PSRAM) and will be rejected
 *   - ADC only works on GPIO 1-10 (ADC1 on ESP32-S3)
 *   - UART port 0 is reserved for the serial CLI
 *   - Bus peripherals (I2C, SPI, UART) are lazily initialized on first use
 *   - All binary data is hex-encoded in tool parameters
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
    mimi.begin();
    mimi.start();
}

void loop() {
    mimi.loop();
}
