# Hikvision Device Login Implementation Guide

## Overview
This guide explains how to authenticate with Hikvision devices and decrypt encrypted data responses. This is based on reverse-engineering the browser-based login implementation.

---

## Authentication Flow

### Step 1: Get Session Capabilities
**Request:**
```
GET /ISAPI/Security/sessionLogin/capabilities?username=admin
Cookie: WebSession_535DE5558C=<random_session_id>
```

**Response:**
```xml
<SessionLoginCap>
  <sessionID>c00c74f9e6d247e8...</sessionID>
  <challenge>8c6604161cf660ae...</challenge>
  <iterations>100</iterations>
  <isIrreversible>true</isIrreversible>
  <salt>OGJPE4PRYYUJ7SZWYKKCWQKLLQ5A76CV...</salt>
  <sessionIDVersion>2</sessionIDVersion>
</SessionLoginCap>
```

### Step 2: Compute Encrypted Password
The password encryption uses SHA-256 with iterations:

**Algorithm (when isIrreversible=true):**
```javascript
// First hash
hash1 = SHA256(username + salt + password)

// Second hash with challenge
hash2 = SHA256(hash1 + challenge)

// Iterate remaining times
for (i = 2; i < iterations; i++) {
    hash2 = SHA256(hash2)
}

encrypted_password = hash2
```

**Algorithm (when isIrreversible=false):**
```javascript
hash = SHA256(password) + challenge

for (i = 1; i < iterations; i++) {
    hash = SHA256(hash)
}

encrypted_password = hash
```

### Step 3: Login Request
**Request:**
```
POST /ISAPI/Security/sessionLogin?timeStamp=<timestamp>&random=<random_number>
Cookie: WebSession_535DE5558C=<session_from_step1>

<?xml version="1.0"?>
<SessionLogin>
  <userName>admin</userName>
  <password>6fecd2559b33edcf2b81...</password>
  <sessionID>c00c74f9e6d247e8...</sessionID>
  <isSessionIDValidLongTerm>false</isSessionIDValidLongTerm>
  <sessionIDVersion>2</sessionIDVersion>
</SessionLogin>
```

**Response:**
```xml
<SessionLogin>
  <statusValue>200</statusValue>
  <statusString>OK</statusString>
</SessionLogin>
```

The server will set a new cookie with the validated sessionID.

### Step 4: Session Heartbeat (Keep-Alive)
**Request:**
```
PUT /ISAPI/Security/sessionHeartbeat
Cookie: WebSession_535DE5558C=<authenticated_session>
```

---

## Data Encryption/Decryption

### AES Key Derivation
When fetching sensitive data (like user info), the device uses AES-256-CBC encryption.

**AES Key Generation:**
```javascript
// Get irreversible key
irreversible_key = SHA256(username + salt + password)

// Generate AES key
aes_key = SHA256(irreversible_key + "AaBbCcDd1234!@#$")

// Iterate for key strengthening
for (i = 1; i < iterations; i++) {
    aes_key = SHA256(aes_key)
}

// Take first 32 characters (256 bits)
aes_key = aes_key.substring(0, 32)
```

### Data Decryption
**Request with security parameter:**
```
POST /ISAPI/AccessControl/UserInfo/Search?format=json&security=1&iv=<random_iv_hex>
Cookie: WebSession_535DE5558C=<authenticated_session>
```

The `iv` parameter is a random 128-bit value (32 hex characters).

**Decryption Process:**
```javascript
// AES-256-CBC Decryption
// Input:
//   - encrypted_data: hex string from response
//   - aes_key: 32 hex characters (derived above)
//   - iv: 32 hex characters (from URL parameter)

// 1. Convert hex to bytes
key_bytes = hex_decode(aes_key)
iv_bytes = hex_decode(iv)
cipher_bytes = hex_decode(encrypted_data)

// 2. Decode using AES-CBC
cipher_base64 = base64_encode(cipher_bytes)
plaintext = AES_DECRYPT_CBC(cipher_base64, key_bytes, iv_bytes, PKCS7_PADDING)

// 3. Decode base64 result
result = base64_decode(plaintext)
```

---

## Implementation for Embedded Devices

### Requirements
Your embedded device needs:
1. **HTTP/HTTPS client** (for API calls)
2. **SHA-256 hashing** (for password encryption and AES key derivation)
3. **AES-256-CBC encryption/decryption** (for data decryption)
4. **Base64 encoding/decoding**
5. **Random number generator** (for IV generation)
6. **XML parser** (or JSON if using format=json)

### Recommended Libraries

#### For Arduino/ESP32:
- **mbedTLS** or **BearSSL**: SHA-256, AES-256-CBC
- **Arduino Base64 library**
- **WiFiClientSecure**: HTTPS support
- **ArduinoJson**: JSON parsing (easier than XML)

#### For Raspberry Pi (Python):
```python
# Install required libraries
pip install requests pycryptodome
```

---

## Python Implementation Example

```python
import hashlib
import secrets
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import requests

class HikvisionClient:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.aes_key = None

    def login(self):
        # Step 1: Get capabilities
        url = f"http://{self.ip}/ISAPI/Security/sessionLogin/capabilities?username={self.username}"
        resp = self.session.get(url)

        # Parse XML response (simplified - use proper XML parser)
        import re
        session_id = re.search(r'<sessionID>(.*?)</sessionID>', resp.text).group(1)
        challenge = re.search(r'<challenge>(.*?)</challenge>', resp.text).group(1)
        iterations = int(re.search(r'<iterations>(.*?)</iterations>', resp.text).group(1))
        salt = re.search(r'<salt>(.*?)</salt>', resp.text).group(1)
        is_irreversible = 'true' in re.search(r'<isIrreversible>(.*?)</isIrreversible>', resp.text).group(1).lower()

        # Step 2: Calculate encrypted password
        encrypted_pwd = self._encrypt_password(
            self.password, self.username, challenge, salt, iterations, is_irreversible
        )

        # Calculate AES key for later use
        self.aes_key = self._derive_aes_key(self.password, self.username, salt, iterations)

        # Step 3: Login
        timestamp = int(time.time() * 1000)
        random_num = secrets.randbelow(100000000)
        login_url = f"http://{self.ip}/ISAPI/Security/sessionLogin?timeStamp={timestamp}&random={random_num}"

        login_xml = f"""<?xml version="1.0"?>
        <SessionLogin>
            <userName>{self.username}</userName>
            <password>{encrypted_pwd}</password>
            <sessionID>{session_id}</sessionID>
            <isSessionIDValidLongTerm>false</isSessionIDValidLongTerm>
            <sessionIDVersion>2</sessionIDVersion>
        </SessionLogin>"""

        resp = self.session.post(login_url, data=login_xml)

        if '<statusValue>200</statusValue>' in resp.text:
            print("Login successful!")
            return True
        else:
            print("Login failed!")
            return False

    def _encrypt_password(self, password, username, challenge, salt, iterations, is_irreversible):
        if is_irreversible:
            # hash1 = SHA256(username + salt + password)
            hash1 = hashlib.sha256((username + salt + password).encode()).hexdigest()
            # hash2 = SHA256(hash1 + challenge)
            hash2 = hashlib.sha256((hash1 + challenge).encode()).hexdigest()
            # Iterate remaining times
            for i in range(2, iterations):
                hash2 = hashlib.sha256(hash2.encode()).hexdigest()
            return hash2
        else:
            # hash = SHA256(password) + challenge
            hash_val = hashlib.sha256(password.encode()).hexdigest() + challenge
            # Iterate
            for i in range(1, iterations):
                hash_val = hashlib.sha256(hash_val.encode()).hexdigest()
            return hash_val

    def _derive_aes_key(self, password, username, salt, iterations):
        # irreversible_key = SHA256(username + salt + password)
        irreversible_key = hashlib.sha256((username + salt + password).encode()).hexdigest()

        # aes_key = SHA256(irreversible_key + "AaBbCcDd1234!@#$")
        aes_key = hashlib.sha256((irreversible_key + "AaBbCcDd1234!@#$").encode()).hexdigest()

        # Iterate
        for i in range(1, iterations):
            aes_key = hashlib.sha256(aes_key.encode()).hexdigest()

        # Take first 32 characters (256 bits)
        return aes_key[:32]

    def decrypt_data(self, encrypted_hex, iv_hex):
        """Decrypt AES-256-CBC encrypted data"""
        # Convert hex to bytes
        key_bytes = bytes.fromhex(self.aes_key)
        iv_bytes = bytes.fromhex(iv_hex)
        cipher_bytes = bytes.fromhex(encrypted_hex)

        # Create cipher
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

        # Decrypt
        decrypted = cipher.decrypt(cipher_bytes)

        # Remove PKCS7 padding
        decrypted = unpad(decrypted, AES.block_size)

        # Base64 decode
        result = b64decode(decrypted).decode('utf-8')

        return result

    def fetch_users(self):
        """Fetch user list with encrypted response"""
        # Generate random IV
        iv = secrets.token_hex(16)  # 16 bytes = 32 hex chars

        url = f"http://{self.ip}/ISAPI/AccessControl/UserInfo/Search?format=json&security=1&iv={iv}"

        payload = {
            "UserInfoSearchCond": {
                "searchID": str(uuid.uuid4()),
                "maxResults": 20,
                "searchResultPosition": 0
            }
        }

        resp = self.session.post(url, json=payload)

        # Parse response and decrypt fields
        data = resp.json()

        for user in data.get('UserInfoSearch', {}).get('UserInfo', []):
            # Decrypt employeeNo and name
            if 'employeeNo' in user:
                user['employeeNo'] = self.decrypt_data(user['employeeNo'], iv)
            if 'name' in user:
                user['name'] = self.decrypt_data(user['name'], iv)

        return data

# Usage
client = HikvisionClient("192.168.1.100", "admin", "yourpassword")
if client.login():
    users = client.fetch_users()
    print(users)
```

---

## C/C++ Implementation Outline (for ESP32/Arduino)

```cpp
#include <WiFi.h>
#include <HTTPClient.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <Base64.h>

class HikvisionClient {
private:
    String ip;
    String username;
    String password;
    String aes_key;
    String session_cookie;

    String sha256(String data) {
        mbedtls_sha256_context ctx;
        unsigned char hash[32];

        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, (unsigned char*)data.c_str(), data.length());
        mbedtls_sha256_finish(&ctx, hash);
        mbedtls_sha256_free(&ctx);

        // Convert to hex string
        String result = "";
        for(int i = 0; i < 32; i++) {
            char hex[3];
            sprintf(hex, "%02x", hash[i]);
            result += hex;
        }
        return result;
    }

    String encryptPassword(String pwd, String user, String challenge,
                          String salt, int iterations, bool irreversible) {
        String hash;

        if (irreversible) {
            hash = sha256(user + salt + pwd);
            hash = sha256(hash + challenge);
            for(int i = 2; i < iterations; i++) {
                hash = sha256(hash);
            }
        } else {
            hash = sha256(pwd) + challenge;
            for(int i = 1; i < iterations; i++) {
                hash = sha256(hash);
            }
        }

        return hash;
    }

    String deriveAESKey(String pwd, String user, String salt, int iterations) {
        String irreversible = sha256(user + salt + pwd);
        String key = sha256(irreversible + "AaBbCcDd1234!@#$");

        for(int i = 1; i < iterations; i++) {
            key = sha256(key);
        }

        return key.substring(0, 32);
    }

public:
    HikvisionClient(String ip, String user, String pass)
        : ip(ip), username(user), password(pass) {}

    bool login() {
        // Implementation similar to Python example
        // 1. GET capabilities
        // 2. Encrypt password
        // 3. POST login
        // 4. Store session cookie

        return true;
    }

    String decryptData(String encrypted_hex, String iv_hex) {
        // AES-256-CBC decryption using mbedtls
        // Implementation needed
        return "";
    }
};
```

---

## Key Challenges for Embedded Devices

1. **Memory Constraints**: The crypto operations require significant RAM
2. **HTTPS/TLS**: Requires TLS libraries (mbedTLS is lightweight)
3. **XML Parsing**: Consider using JSON format instead (`format=json`)
4. **Session Management**: Need to handle cookies and heartbeat

### Recommendations:

1. **Use ESP32 over Arduino**: More RAM and built-in WiFi/TLS
2. **Use JSON instead of XML**: Lighter parsing with ArduinoJson
3. **Request only needed fields**: Minimize response size
4. **Implement session heartbeat**: Keep connection alive with periodic PUT requests
5. **Error handling**: Handle network failures and re-login when needed

---

## Security Notes

1. **Always use HTTPS in production** to prevent password interception
2. **The salt is sent in plaintext** but this is by design
3. **Session cookies should be protected** - use HttpOnly flags
4. **Change default passwords** on Hikvision devices
5. **The AES key never leaves the client** - it's derived, not transmitted

---

## Testing

You can test the implementation with these tools:
- **Postman**: For testing API calls
- **Python script**: For quick prototyping
- **Browser DevTools**: To capture actual traffic and compare

The encrypted user data you see (employeeNo, name fields) are encrypted with the AES key and can be decrypted using the IV from the query parameter.
