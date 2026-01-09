# Hikvision ESP32 Client

Full-featured ESP32 Arduino sketch for Hikvision devices, matching the functionality of `hikvision_client.py`.

## Features

✅ **Encrypted Session Login** - SHA256-based authentication with salt and iterations
✅ **Fetch Device Information** - Get device details
✅ **Fetch User List** - Retrieve all registered users with plaintext data
✅ **Fetch Attendance Events** - Get access control events (check-in/check-out records)
✅ **Automatic Heartbeat** - Keeps session alive automatically

## Hardware Requirements

- **ESP32 Development Board** (any variant)
- WiFi connection
- Micro-USB cable for programming

## Software Requirements

### Arduino IDE Setup

1. **Install Arduino IDE** (version 1.8.x or 2.x)
   - Download from: https://www.arduino.cc/en/software

2. **Add ESP32 Board Support**
   - Open Arduino IDE
   - Go to `File` → `Preferences`
   - Add to "Additional Board Manager URLs":
     ```
     https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
     ```
   - Go to `Tools` → `Board` → `Boards Manager`
   - Search for "esp32" and install "esp32 by Espressif Systems"

3. **Install Required Libraries**
   - Go to `Sketch` → `Include Library` → `Manage Libraries`
   - Search and install:
     - **ArduinoJson** (by Benoit Blanchon) - Version 6.x

   Built-in libraries (no installation needed):
   - WiFi
   - HTTPClient
   - mbedtls (for SHA256)

### PlatformIO Setup (Alternative)

If using PlatformIO, add to `platformio.ini`:

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps =
    bblanchon/ArduinoJson@^6.21.3
```

## Configuration

Edit the configuration section at the top of `esp32_example.ino`:

```cpp
// WiFi credentials
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

// Hikvision device credentials
const char* HIK_IP = "102.217.127.12";
const char* HIK_USERNAME = "admin";
const char* HIK_PASSWORD = "dev@spa!";
const bool USE_HTTPS = false;
```

## Uploading to ESP32

1. Connect ESP32 to computer via USB
2. Select your board:
   - `Tools` → `Board` → `ESP32 Arduino` → `ESP32 Dev Module`
3. Select correct COM port:
   - `Tools` → `Port` → Select your ESP32's port
4. Click **Upload** button (→)

## Usage

### Serial Monitor

1. Open Serial Monitor: `Tools` → `Serial Monitor`
2. Set baud rate to **115200**
3. Watch the output as the ESP32:
   - Connects to WiFi
   - Logs into Hikvision device
   - Fetches device info
   - Retrieves user list (5 users)
   - Fetches today's attendance events (10 events)

### Customizing Functions

To call functions with different parameters, modify the `setup()` function:

```cpp
void setup() {
  // ... WiFi and login code ...

  // Fetch 20 users instead of 5
  fetchUsers(20);

  // Fetch 50 events instead of 10
  fetchEvents(50);

  // Fetch events for specific date range
  fetchEvents(30, "2026-01-06T00:00:00+03:00", "2026-01-06T23:59:59+03:00");
}
```

## Available Functions

### `hikvisionLogin()`
Authenticates with the Hikvision device using encrypted session login.

**Returns:** `bool` - true if successful

```cpp
if (hikvisionLogin()) {
  Serial.println("Logged in!");
}
```

### `getDeviceInfo()`
Retrieves and displays device information (XML format).

```cpp
getDeviceInfo();
```

### `fetchUsers(int maxResults)`
Fetches registered users from the device.

**Parameters:**
- `maxResults` - Maximum number of users to retrieve (default: 10)

```cpp
fetchUsers(20);  // Fetch 20 users
```

**Output includes:**
- Employee Number
- Name
- User Type
- Number of faces/fingerprints/cards registered

### `fetchEvents(int maxResults, String startTime, String endTime)`
Fetches access control events (attendance records).

**Parameters:**
- `maxResults` - Maximum number of events (default: 10)
- `startTime` - Start time in ISO format with timezone (default: today 00:00:00)
- `endTime` - End time in ISO format with timezone (default: today 23:59:59)

```cpp
// Fetch today's events (default)
fetchEvents(10);

// Fetch specific date range
fetchEvents(50, "2026-01-06T00:00:00+03:00", "2026-01-06T23:59:59+03:00");
```

**Output includes:**
- Timestamp
- Employee Number & Name
- Door Number
- Attendance Status (checkIn/checkOut)
- Verification Mode (card/face/fingerprint)

### `sendHeartbeat()`
Sends heartbeat to keep session alive (automatically called every 60 seconds in loop).

**Returns:** `bool` - true if successful

```cpp
if (sendHeartbeat()) {
  Serial.println("Session kept alive");
}
```

## Sample Output

```
========================================
   Hikvision ESP32 Client
========================================

[*] Connecting to WiFi...
[*] SSID: MyWiFi
.....
[+] WiFi connected!
[*] IP address: 192.168.1.100

[*] Connecting to Hikvision device...
[*] IP: 102.217.127.12
[*] Step 1: Getting session capabilities...
    Session ID: f22255d756bbbbd153b1d520bf54a21c...
    Challenge: 8a46fa3cbde9241d710bf361148dfe6c
    Iterations: 100
    Salt: NR6SR6TEKJ7R0AYD4URZDFCLAHDLMEKA...
    Irreversible: true
[*] Step 2: Encrypting password...
    Encrypted password: 57d0d6d200b8442f5639fe9ad8e94fba...
[*] Step 3: Deriving AES key...
    AES Key: 97be3ad37e375ee3b349c98b38456dde
[*] Step 4: Performing login...
[+] Login successful!

========================================
   Running Demonstrations
========================================

[*] Fetching users...
[*] Found 5 users (total: 48)

  User 1:
    Employee No: SPA0011
    Name: James Wanyoike
    Type: normal
    Faces: 1
    Fingerprints: 2
    Cards: 0

[*] Fetching access control events...
[*] Found 10 events (total: 138)

  Event 1:
    Time: 2026-01-07T05:10:04+03:00
    Employee: SPA0033
    Name: David Ngatia
    Door: 1
    Status: checkIn
    Verify Mode: cardOrFaceOrFp

========================================
   Demo Complete - Entering Loop
========================================

[*] Heartbeat sent successfully
```

## Troubleshooting

### "Failed to connect to WiFi"
- Check SSID and password are correct
- Ensure WiFi network is 2.4GHz (ESP32 doesn't support 5GHz)
- Move ESP32 closer to router

### "Failed to get capabilities"
- Check Hikvision device IP address is correct
- Ensure device is on same network as ESP32
- Try pinging the device IP from your computer

### "Login failed"
- Verify username and password are correct
- Check if device uses HTTPS (set `USE_HTTPS = true`)
- Ensure device firmware is up to date

### "Compilation errors"
- Make sure ArduinoJson library is installed (version 6.x)
- Verify ESP32 board support is installed
- Try selecting different ESP32 board variant

### Memory Issues
If you get heap/memory errors:
- Reduce `maxResults` in function calls
- Reduce JSON document sizes in code (change `DynamicJsonDocument` sizes)

## Comparison with Python Client

| Feature | Python | ESP32 | Status |
|---------|--------|-------|--------|
| Encrypted Login | ✅ | ✅ | Working |
| Fetch Device Info | ✅ | ✅ | Working |
| Fetch Users (plaintext) | ✅ | ✅ | Working |
| Fetch Events (plaintext) | ✅ | ✅ | Working |
| Session Heartbeat | ✅ | ✅ | Working |
| Encrypted Response Decryption | ❌ | ❌ | Not implemented yet |

Both implementations use plaintext mode for fetching users and events, which works perfectly and returns all the data needed.

## License

MIT License - Free to use and modify

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Verify your device credentials and network settings
3. Check Serial Monitor output for detailed error messages
