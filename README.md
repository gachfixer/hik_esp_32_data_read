# Hikvision Device Authentication & Data Extraction

This repository contains code and documentation for authenticating with Hikvision devices (cameras, DVRs, access control systems) and extracting encrypted data.

## Files Overview

- **IMPLEMENTATION_GUIDE.md** - Detailed technical documentation of the authentication protocol
- **hikvision_client.py** - Complete Python implementation
- **esp32_example.ino** - Arduino/ESP32 example code
- **requirements.txt** - Python dependencies
- **login_call_sequence.txt** - Captured login sequence from browser

## Quick Start (Python)

### 1. Install Requirements

```bash
pip install -r requirements.txt
```

### 2. Run the Client

```bash
# Basic login and device info
python hikvision_client.py 192.168.1.100 -u admin -p your_password --info

# Fetch encrypted user data
python hikvision_client.py 192.168.1.100 -u admin -p your_password --users

# Get streaming channels
python hikvision_client.py 192.168.1.100 -u admin -p your_password --channels

# Use HTTPS (recommended for production)
python hikvision_client.py 192.168.1.100 -u admin -p your_password --https --info
```

### 3. Example Output

```
[*] Connecting to http://192.168.1.100
[*] Step 1: Getting session capabilities...
    Session ID: c00c74f9e6d247e8dc099f919c56b3c8...
    Challenge: 8c6604161cf660ae7f280318c8ae126a
    Iterations: 100
    Salt: OGJPE4PRYYUJ7SZWYKKCWQKLLQ5A76CV...
    Irreversible: True
[*] Step 2: Encrypting password...
    Encrypted password: 6fecd2559b33edcf2b8100005db36ecb...
[*] Step 3: Deriving AES key...
    AES Key: a1b2c3d4e5f6...
[*] Step 4: Performing login...
[+] Login successful!

[*] Fetching users (IV: eab2dddeb04956ef902ded507b1ce0b1)...
[*] Found 20 users
    Employee No (encrypted): 742495974a11de876eb99e86a8611eb6
    Employee No (decrypted): 12345
    Name (encrypted): 5fd6d13d20137916d4edae65b9d9dbc6...
    Name (decrypted): John Doe
```

## Quick Start (ESP32/Arduino)

### 1. Install Required Libraries

Using Arduino IDE Library Manager, install:
- **ArduinoJson** by Benoit Blanchon
- **Base64** by Arturo Guadalupi

### 2. Configure the Code

Edit `esp32_example.ino`:

```cpp
// WiFi credentials
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

// Hikvision device credentials
const char* hik_ip = "192.168.1.100";
const char* hik_username = "admin";
const char* hik_password = "your_device_password";
```

### 3. Upload and Run

1. Open `esp32_example.ino` in Arduino IDE
2. Select your ESP32 board from Tools > Board
3. Select the correct COM port
4. Click Upload
5. Open Serial Monitor (115200 baud)

## How It Works

### Authentication Process

1. **Get Capabilities** - Request session info including challenge and salt
2. **Hash Password** - Use SHA-256 with iterations to create secure hash
3. **Login** - Send credentials with hashed password
4. **Derive AES Key** - Generate key for decrypting data responses
5. **Heartbeat** - Keep session alive with periodic requests

### Data Encryption

Hikvision uses AES-256-CBC encryption for sensitive data fields:
- Employee numbers
- Names
- Other personal information

The encryption key is derived from your password and never transmitted. Each request uses a random IV (Initialization Vector) for security.

### Key Components

```
Password Hashing:
  SHA256(username + salt + password) -> hash1
  SHA256(hash1 + challenge) -> hash2
  Iterate SHA256(hash2) 100 times

AES Key Derivation:
  SHA256(username + salt + password) -> irreversible_key
  SHA256(irreversible_key + "AaBbCcDd1234!@#$") -> aes_key
  Iterate SHA256(aes_key) 100 times
  Take first 32 hex characters (128 bits)
```

## API Endpoints

### Common Endpoints

```
# Authentication
GET  /ISAPI/Security/sessionLogin/capabilities?username=<user>
POST /ISAPI/Security/sessionLogin
PUT  /ISAPI/Security/sessionHeartbeat

# Device Info
GET  /ISAPI/System/deviceInfo
GET  /ISAPI/System/capabilities

# Video Streaming
GET  /ISAPI/Streaming/channels
GET  /ISAPI/Streaming/channels/<id>

# Access Control (requires security=1&iv=<random_iv>)
POST /ISAPI/AccessControl/UserInfo/Search?format=json&security=1&iv=<iv>
GET  /ISAPI/AccessControl/UserInfo/Record?format=json&security=1&iv=<iv>

# Events
POST /ISAPI/Event/triggers/peopleDetection
POST /ISAPI/Smart/FieldDetection/1
```

## Security Considerations

1. **Always use HTTPS in production** to prevent man-in-the-middle attacks
2. **Change default passwords** - Hikvision devices often ship with default credentials
3. **Firewall your devices** - Don't expose them directly to the internet
4. **Keep firmware updated** - Check for security updates regularly
5. **Strong passwords** - Use complex passwords for device authentication
6. **Session management** - Always logout when done and implement timeout

## Limitations

### Embedded Devices

- **Memory**: Crypto operations require significant RAM (ESP32 recommended over Arduino Uno)
- **Processing**: SHA-256 iterations can be slow on low-power MCUs
- **Libraries**: Need mbedtls or similar for crypto operations
- **HTTPS**: TLS/SSL adds memory and processing overhead

### Recommendations for Embedded

- Use ESP32 (520KB RAM) instead of Arduino (2KB RAM)
- Request only the data you need to minimize response size
- Use JSON format instead of XML (lighter parsing)
- Implement error handling and automatic re-login
- Consider using a gateway device (Raspberry Pi) for complex operations

## Troubleshooting

### Login Failed

- Check IP address and network connectivity
- Verify username and password
- Ensure device firmware supports session login v2
- Check if device is locked due to failed login attempts

### Decryption Failed

- Verify AES key derivation matches device settings
- Ensure IV parameter is correctly generated (32 hex chars)
- Check that encrypted data is valid hex string
- Verify iterations count matches device capabilities

### SSL/HTTPS Issues

```python
# For self-signed certificates, disable verification (testing only!)
client = HikvisionClient(ip, user, pass, use_https=True)
# The client automatically sets verify=False for self-signed certs
```

## Additional Resources

- [Hikvision ISAPI Documentation](http://oversea-download.hikvision.com/uploadfile/Leaflet/ISAPI/HIKVISION%20ISAPI_2.0-IPMD%20Service.pdf)
- [ESP32 Arduino Core](https://github.com/espressif/arduino-esp32)
- [mbedTLS Documentation](https://tls.mbed.org/)

## Tested Devices

This implementation has been tested with:
- Hikvision DS-K1T671 Series (Access Control)
- Hikvision IP Cameras with firmware V5.x
- Other ISAPI-compatible devices

## License

This code is provided for educational and authorized security testing purposes only. Always ensure you have proper authorization before accessing any device.

## Contributing

If you find issues or have improvements:
1. Test with your specific device
2. Document any device-specific quirks
3. Share findings (without exposing security vulnerabilities publicly)

## Disclaimer

This code is for authorized use only. Unauthorized access to devices is illegal. Always obtain proper permission before testing or accessing any system you do not own.
