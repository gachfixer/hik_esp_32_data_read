# Hikvision Client V2 - Changes Summary

## Overview
Version 2 implements sessionTag support as specified in the updated login sequence. This matches the sessionIDVersion 2 protocol that Hikvision devices now use.

## Key Changes from V1 to V2

### 1. **Capabilities Request (Step 1)**
**Old (V1):**
```
GET /ISAPI/Security/sessionLogin/capabilities?username=admin
```

**New (V2):**
```
GET /ISAPI/Security/sessionLogin/capabilities?username=admin&random=30411234
```
- Added `random` parameter with a random number (0-99999999)

---

### 2. **Login Request (Step 4)**
**Old (V1) XML:**
```xml
<SessionLogin>
    <userName>admin</userName>
    <password>8773955c7f9d1856037203aa0cb38fa9c269cb75704ae6e039d3fe18f2eff3ab</password>
    <sessionID>6eebffac2860f6b598dd5b2a21df911a76953cc2222936149ba6bd259379fdd7</sessionID>
    <isSessionIDValidLongTerm>false</isSessionIDValidLongTerm>
    <sessionIDVersion>2</sessionIDVersion>
</SessionLogin>
```

**New (V2) XML:**
```xml
<SessionLogin>
    <userName>admin</userName>
    <password>8773955c7f9d1856037203aa0cb38fa9c269cb75704ae6e039d3fe18f2eff3ab</password>
    <sessionID>6eebffac2860f6b598dd5b2a21df911a76953cc2222936149ba6bd259379fdd7</sessionID>
    <isSessionIDValidLongTerm>false</isSessionIDValidLongTerm>
    <sessionIDVersion>2</sessionIDVersion>
    <isNeedSessionTag>true</isNeedSessionTag>  <!-- NEW -->
</SessionLogin>
```
- Added `<isNeedSessionTag>true</isNeedSessionTag>` element

---

### 3. **Login Response**
**Old (V1) Response:**
```xml
<SessionLogin>
    <statusValue>200</statusValue>
    <statusString>OK</statusString>
    <isDefaultPassword>false</isDefaultPassword>
    <isRiskPassword>false</isRiskPassword>
    <isActivated>true</isActivated>
    <sessionIDVersion>2</sessionIDVersion>
</SessionLogin>
```

**New (V2) Response:**
```xml
<SessionLogin>
    <statusValue>200</statusValue>
    <statusString>OK</statusString>
    <isDefaultPassword>false</isDefaultPassword>
    <isRiskPassword>false</isRiskPassword>
    <isActivated>true</isActivated>
    <sessionTag>S5HU9PGSEO85NK9NFLKTYBQ0LL1MT94EVFQXR0ER4R5TP4LFBZZE6LUCZ77PFPDZ</sessionTag>  <!-- NEW -->
    <sessionIDVersion>2</sessionIDVersion>
</SessionLogin>
```
- Response now includes `<sessionTag>` element that must be extracted and stored

---

### 4. **Subsequent API Requests**
**Old (V1) Headers:**
```
Cookie: WebSession_52B5CFF078=8f67a33fa8cb3ed7a9a5df99884f2d95839476aff45c319d342b64844436c943
```

**New (V2) Headers:**
```
Cookie: WebSession_52B5CFF078=8f67a33fa8cb3ed7a9a5df99884f2d95839476aff45c319d342b64844436c943
sessiontag: S5HU9PGSEO85NK9NFLKTYBQ0LL1MT94EVFQXR0ER4R5TP4LFBZZE6LUCZ77PFPDZ
```
- All subsequent requests MUST include both:
  1. Cookie header (from session)
  2. **sessiontag header** (NEW - extracted from login response)

---

## Implementation Details

### Python (hikvision_client_v2.py)

**New Class Variables:**
```python
self.session_tag = None  # Store sessionTag
```

**New Helper Method:**
```python
def _add_session_headers(self, headers=None):
    """Add session cookie and sessionTag to request headers"""
    if headers is None:
        headers = {}
    if self.session_tag:
        headers['sessiontag'] = self.session_tag
    return headers
```

**Updated Methods:**
All API methods now call `_add_session_headers()` to include sessiontag:
- `heartbeat()`
- `get_device_info()`
- `get_security_capabilities()` (NEW method)
- `get_streaming_channels()`
- `fetch_events()`
- `fetch_users()`

---

### ESP32 (esp32_hikvision_v2.ino)

**New Global Variables:**
```cpp
String sessionTag = "";  // Store sessionTag
```

**Updated Login Function:**
```cpp
// Extract sessionTag from login response
String sessionTagResponse = extractXMLTag(response, "sessionTag");
if (sessionTagResponse.length() > 0) {
    sessionTag = sessionTagResponse;
    Serial.printf("    Session Tag: %s...\n", sessionTag.substring(0, 32).c_str());
}
```

**Updated API Functions:**
All API functions now add sessiontag header:
```cpp
if (sessionTag.length() > 0) {
    http.addHeader("sessiontag", sessionTag);
}
```

Functions updated:
- `sendHeartbeat()`
- `getDeviceInfo()`
- `getSecurityCapabilities()` (NEW function)
- `fetchUsersPlaintext()`
- `fetchUsers()`
- `fetchEvents()`

---

## Testing Sequence

Based on login_call_sequence.txt, the complete flow is:

1. **GET** `/ISAPI/Security/sessionLogin/capabilities?username=admin&random=30411234`
   - Response includes: sessionID, challenge, salt, iterations, isSupportSessionTag, sessionIDVersion

2. **POST** `/ISAPI/Security/sessionLogin?timeStamp=1767938830336`
   - Request includes: `<isNeedSessionTag>true</isNeedSessionTag>`
   - Response includes: `<sessionTag>...</sessionTag>`

3. **GET** `/ISAPI/Security/capabilities?username=admin`
   - Headers: Cookie + sessiontag
   - Response: Security capabilities

4. **POST** `/ISAPI/AccessControl/UserInfo/Search?format=json&security=1&iv=...`
   - Headers: Cookie + sessiontag
   - Response: Encrypted user data

---

## Files Created

1. **hikvision_client_v2.py** - Python client with sessionTag support
2. **esp32_hikvision_v2.ino** - ESP32 Arduino sketch with sessionTag support
3. **V2_CHANGES_SUMMARY.md** - This document

## Configuration Required

### For Python:
```bash
python hikvision_client_v2.py 10.10.1.142 -u admin -p YourPassword --users
```

### For ESP32:
Edit the configuration section in `esp32_hikvision_v2.ino`:
```cpp
const char* WIFI_SSID = "YourWiFiSSID";
const char* WIFI_PASSWORD = "YourWiFiPassword";
const char* HIK_IP = "10.10.1.142";
const char* HIK_USERNAME = "admin";
const char* HIK_PASSWORD = "YourPassword";
```

---

## Compatibility

- **V2** supports devices with sessionIDVersion 2 and sessionTag support
- **V1** works with older devices or devices without sessionTag support
- Both versions maintain the same core functionality (login, fetch users, fetch events, etc.)
- The sessionTag is automatically handled if the device supports it

---

## Security Notes

The sessionTag provides an additional layer of session security:
- Combines with the session cookie for authentication
- Must be included in all subsequent requests
- Extracted from login response and stored for the session lifetime
- Invalidated when session expires or user logs out
