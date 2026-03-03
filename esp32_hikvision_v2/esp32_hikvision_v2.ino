/**
 * Hikvision Client for ESP32 V2
 *
 * Full-featured client with sessionTag support (sessionIDVersion 2)
 *
 * Features:
 * - Encrypted session login with sessionTag
 * - Fetch device information
 * - Fetch security capabilities
 * - Fetch user list (with encryption support)
 * - Fetch access control events (attendance records)
 * - Automatic session heartbeat
 *
 * Required Libraries:
 * - WiFi (built-in)
 * - HTTPClient (built-in)
 * - mbedtls (built-in with ESP32)
 * - ArduinoJson v6 (install via Library Manager)
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <HTTPUpdate.h>
#include <ArduinoJson.h>
#include "mbedtls/md.h"

// ======================== CONFIGURATION ========================

// Firmware version
#define FIRMWARE_VERSION "1.0.0"

// OTA update configuration
const char* OTA_VERSION_URL = "http://102.217.125.188:8084/api/version/kivaywa";
const char* OTA_FIRMWARE_URL = "http://102.217.125.188:8084/kivaywa.bin";
const unsigned long OTA_CHECK_INTERVAL = 30UL * 60 * 1000;  // Check every 30 minutes
static unsigned long lastOTACheck = 0;

// WiFi credentials kivaywa code

const char* WIFI_SSID = "TP-Link_DD78";
const char* WIFI_PASSWORD = "Kivaywa.2026@Tifter";

// Hikvision device credentials
const char* HIK_IP = "192.168.1.103";
const char* HIK_IPP = "192.168.0.176";
const char* HIK_USERNAME = "admin";
const char* HIK_PASSWORD = "dev@spa!";
const bool USE_HTTPS = false;

static unsigned long lastHeartbeat = 0;

// Auto-restart configuration (in milliseconds)
const unsigned long RESTART_AFTER_UPTIME   = 4UL * 60 * 60 * 1000;  // 4 hours
const unsigned long RESTART_WIFI_FAIL_MS   = 20UL * 60 * 1000;      // 20 minutes
const unsigned long RESTART_HIK_FAIL_MS    = 20UL * 60 * 1000;      // 20 minutes

// Failure tracking timestamps (0 = no failure in progress)
static unsigned long wifiFailSince = 0;
static unsigned long hikFailSince  = 0;

// Server to send attendance data
const char* TRACKER_SERVER = "http://102.217.125.188:8084";

// ======================== GLOBAL VARIABLES ========================

String sessionCookie = "";
String sessionTag = "";  // NEW: Store sessionTag
String aesKey = "";
bool isLoggedIn = false;
String deviceId = "";  // ESP32 unique device ID

// Event tracking - start time for fetching events (updated as we process)
String lastEventTime = "";  // Will be set to today's start time initially

// URL parsing structure
typedef struct {
  String host;
  int port;
  bool isHttps;
} UrlParts;

// ======================== HELPER FUNCTIONS ========================

/**
 * Connect or reconnect to WiFi
 * Returns true if connected successfully, false otherwise
 */
bool connectWiFi(bool isReconnect = false) {
  if (isReconnect) {
    Serial.println("[!] WiFi disconnected, reconnecting...");

    // Reset login state since we lost connection
    isLoggedIn = false;
    sessionCookie = "";
    sessionTag = "";

    WiFi.disconnect();
  } else {
    Serial.printf("[*] Connecting to WiFi: %s", WIFI_SSID);
    WiFi.mode(WIFI_STA);
  }

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println(" OK");
    Serial.printf("[*] IP: %s | RSSI: %d dBm\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
    return true;
  } else {
    if (isReconnect) {
      Serial.println(" FAILED");
      Serial.println("[!] WiFi reconnect failed, will retry...");
    } else {
      Serial.println("\n[!] WiFi connection failed!");
    }
    return false;
  }
}

/**
 * Calculate SHA-256 hash of input string
 */
String sha256(const String& data) {
  byte hash[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char*)data.c_str(), data.length());
  mbedtls_md_finish(&ctx, hash);
  mbedtls_md_free(&ctx);

  // Convert to hex string
  String result = "";
  for(int i = 0; i < 32; i++) {
    char hex[3];
    sprintf(hex, "%02x", hash[i]);
    result += hex;
  }
  return result;
}

/**
 * Generate random hex string
 */
String randomHex(int bytes) {
  String result = "";
  for(int i = 0; i < bytes; i++) {
    char hex[3];
    sprintf(hex, "%02x", random(256));
    result += hex;
  }
  return result;
}

/**
 * Generate UUID v4
 */
String generateUUID() {
  return randomHex(4) + "-" + randomHex(2) + "-" + randomHex(2) +
         "-" + randomHex(2) + "-" + randomHex(6);
}

/**
 * Extract XML tag value (simple parser)
 */
String extractXMLTag(const String& xml, const String& tagName) {
  String startTag = "<" + tagName + ">";
  String endTag = "</" + tagName + ">";

  int startIndex = xml.indexOf(startTag);
  if (startIndex == -1) return "";

  startIndex += startTag.length();
  int endIndex = xml.indexOf(endTag, startIndex);
  if (endIndex == -1) return "";

  return xml.substring(startIndex, endIndex);
}

/**
 * Get current timestamp in ISO format
 */
String getISOTimestamp(int hourOffset = 0, int minuteOffset = 0, int secondOffset = 0) {
  time_t now = time(nullptr);
  struct tm timeinfo;
  localtime_r(&now, &timeinfo);  // Use local time (respects configTime timezone)

  timeinfo.tm_hour += hourOffset;
  timeinfo.tm_min += minuteOffset;
  timeinfo.tm_sec += secondOffset;
  mktime(&timeinfo);

  char buffer[30];
  sprintf(buffer, "%04d-%02d-%02dT%02d:%02d:%02d+08:00",
          timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
          timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
  return String(buffer);
}

/**
 * Get ESP32 unique device ID (MAC address based)
 */
String getDeviceId() {
  uint64_t chipId = ESP.getEfuseMac();
  char id[18];
  sprintf(id, "%04X%08X", (uint16_t)(chipId >> 32), (uint32_t)chipId);
  return String(id);
}

// ======================== TRACKER SERVER FUNCTIONS ========================

/**
 * Parse URL into components (host, port, isHttps)
 */
UrlParts parseUrl(const String& url) {
  UrlParts parts;
  parts.isHttps = url.startsWith("https://");
  parts.port = parts.isHttps ? 443 : 80;

  // Remove protocol
  String remaining = url;
  if (parts.isHttps) {
    remaining = url.substring(8);  // Remove "https://"
  } else if (url.startsWith("http://")) {
    remaining = url.substring(7);  // Remove "http://"
  }

  // Find port if specified (host:port)
  int colonPos = remaining.indexOf(':');
  int slashPos = remaining.indexOf('/');

  if (colonPos > 0 && (slashPos < 0 || colonPos < slashPos)) {
    parts.host = remaining.substring(0, colonPos);
    if (slashPos > 0) {
      parts.port = remaining.substring(colonPos + 1, slashPos).toInt();
    } else {
      parts.port = remaining.substring(colonPos + 1).toInt();
    }
  } else if (slashPos > 0) {
    parts.host = remaining.substring(0, slashPos);
  } else {
    parts.host = remaining;
  }

  return parts;
}

/**
 * Get last event time from server
 * POST /mobile/getLastTime/{deviceId}
 * Returns the time string or empty string on failure
 */
String getLastTimeFromServer() {
  if (deviceId.length() == 0) {
    deviceId = getDeviceId();
  }

  UrlParts server = parseUrl(String(TRACKER_SERVER));
  String path = "/mobile/getLastTime/" + deviceId;

  Serial.printf("[*] Getting last time from: %s:%d%s\n",
                server.host.c_str(), server.port, path.c_str());

  // Connect using appropriate client
  WiFiClient* client;
  WiFiClientSecure secureClient;
  WiFiClient insecureClient;

  if (server.isHttps) {
    secureClient.setInsecure();
    client = &secureClient;
  } else {
    client = &insecureClient;
  }

  if (!client->connect(server.host.c_str(), server.port)) {
    Serial.println("[!] Connection failed");
    return "";
  }

  // Send POST request
  client->println("POST " + path + " HTTP/1.1");
  client->println("Host: " + server.host + ":" + String(server.port));
  client->println("Content-Type: application/json");
  client->println("Content-Length: 0");
  client->println("Connection: close");
  client->println();

  // Wait for response
  unsigned long timeout = millis();
  while (client->available() == 0) {
    if (millis() - timeout > 10000) {
      Serial.println("[!] Response timeout");
      client->stop();
      return "";
    }
  }

  // Read response
  String response = "";
  while (client->available()) {
    response += client->readStringUntil('\n') + "\n";
  }
  client->stop();

  // Check for success
  if (!response.startsWith("HTTP/1.1 200")) {
    Serial.println("[!] Failed to get last time");
    return "";
  }

  // Extract body (after empty line)
  int bodyStart = response.indexOf("\r\n\r\n");
  if (bodyStart < 0) {
    bodyStart = response.indexOf("\n\n");
  }

  if (bodyStart < 0) {
    return "";
  }

  String lastTime = response.substring(bodyStart + 4);
  lastTime.trim();

  Serial.println("[*] Last time from server: " + lastTime);
  return lastTime;
}

/**
 * Send attendance event to tracker server
 * Automatically uses HTTPS or HTTP based on TRACKER_SERVER URL
 */
bool sendEventToServer(const char* employeeNo, const char* name, const char* eventTime,
                       int doorNo, const char* attendanceStatus, const char* verifyMode) {

  if (deviceId.length() == 0) {
    deviceId = getDeviceId();
  }

  // Parse server URL
  UrlParts server = parseUrl(String(TRACKER_SERVER));
  String path = "/mobile/esp32AttendanceData/" + deviceId;

  // Create JSON payload
  DynamicJsonDocument doc(512);
  doc["deviceId"] = deviceId;
  doc["employeeNo"] = employeeNo;
  doc["name"] = name;
  doc["eventTime"] = eventTime;
  doc["doorNo"] = String(doorNo);
  doc["attendanceStatus"] = attendanceStatus;
  doc["verifyMode"] = verifyMode;

  String payload;
  serializeJson(doc, payload);

  Serial.printf("[*] POST to: %s:%d%s (%s)\n",
                server.host.c_str(), server.port, path.c_str(),
                server.isHttps ? "HTTPS" : "HTTP");
  Serial.println("[*] Body: " + payload);

  // Connect using appropriate client
  WiFiClient* client;
  WiFiClientSecure secureClient;
  WiFiClient insecureClient;

  if (server.isHttps) {
    secureClient.setInsecure();  // Skip certificate verification
    client = &secureClient;
  } else {
    client = &insecureClient;
  }

  if (!client->connect(server.host.c_str(), server.port)) {
    Serial.println("[!] Connection failed");
    return false;
  }

  // Send HTTP request
  client->println("POST " + path + " HTTP/1.1");
  client->println("Host: " + server.host + ":" + String(server.port));
  client->println("Content-Type: application/json");
  client->println("Connection: close");
  client->print("Content-Length: ");
  client->println(payload.length());
  client->println();
  client->println(payload);

  // Wait for response
  unsigned long timeout = millis();
  while (client->available() == 0) {
    if (millis() - timeout > 10000) {
      Serial.println("[!] Response timeout");
      client->stop();
      return false;
    }
  }

  // Read response
  String response = "";
  while (client->available()) {
    response += client->readStringUntil('\n') + "\n";
  }
  client->stop();

  Serial.println("[*] Response:");
  Serial.println(response.substring(0, 200));

  // Check for success
  bool success = response.startsWith("HTTP/1.1 200") || response.startsWith("HTTP/1.1 201");
  if (success) {
    Serial.println("[+] Send OK");
  } else {
    Serial.println("[!] Send failed");
  }

  return success;
}

// ======================== HIKVISION FUNCTIONS ========================

/**
 * Encrypt password according to Hikvision algorithm
 */
String encryptPassword(const String& pwd, const String& user, const String& challenge,
                       const String& salt, int iterations, bool irreversible) {
  String hash;

  if (irreversible) {
    // hash1 = SHA256(username + salt + password)
    hash = sha256(user + salt + pwd);
    // hash2 = SHA256(hash1 + challenge)
    hash = sha256(hash + challenge);
    // Iterate remaining times
    for(int i = 2; i < iterations; i++) {
      hash = sha256(hash);
    }
  } else {
    // hash = SHA256(password) + challenge
    hash = sha256(pwd) + challenge;
    // Iterate
    for(int i = 1; i < iterations; i++) {
      hash = sha256(hash);
    }
  }

  return hash;
}

/**
 * Derive AES key for data decryption
 */
String deriveAESKey(const String& pwd, const String& user, const String& salt,
                    int iterations, bool irreversible) {
  String irreversible_key;

  if (irreversible) {
    irreversible_key = sha256(user + salt + pwd);
  } else {
    irreversible_key = sha256(pwd);
  }

  // aes_key = SHA256(irreversible_key + "AaBbCcDd1234!@#$")
  String key = sha256(irreversible_key + "AaBbCcDd1234!@#$");

  // Iterate
  for(int i = 1; i < iterations; i++) {
    key = sha256(key);
  }

  // Take first 32 characters for 128-bit AES key
  return key.substring(0, 32);
}

/**
 * Login to Hikvision device with sessionTag support
 */
bool hikvisionLogin() {
  HTTPClient http;

  String protocol = USE_HTTPS ? "https://" : "http://";
  int randomNum = random(100000000);
  String capUrl = protocol + String(HIK_IP) +
                  "/ISAPI/Security/sessionLogin/capabilities?username=" +
                  String(HIK_USERNAME) + "&random=" + String(randomNum);

  http.begin(capUrl);
  http.setTimeout(10000);
  http.addHeader("Accept", "*/*");
  int httpCode = http.GET();

  if (httpCode != 200) {
    http.end();
    return false;
  }

  String response = http.getString();
  http.end();

  // Parse XML response
  String sessionID = extractXMLTag(response, "sessionID");
  String challenge = extractXMLTag(response, "challenge");
  String iterationsStr = extractXMLTag(response, "iterations");
  String salt = extractXMLTag(response, "salt");
  String irreversibleStr = extractXMLTag(response, "isIrreversible");
  String sessionIDVersionStr = extractXMLTag(response, "sessionIDVersion");

  if (sessionID.length() == 0 || challenge.length() == 0) {
    return false;
  }

  int iterations = iterationsStr.toInt();
  bool irreversible = irreversibleStr.equalsIgnoreCase("true");
  int sessionIDVersion = sessionIDVersionStr.toInt();

  // Encrypt password
  String encryptedPwd = encryptPassword(HIK_PASSWORD, HIK_USERNAME,
                                        challenge, salt, iterations, irreversible);

  // Derive AES key
  aesKey = deriveAESKey(HIK_PASSWORD, HIK_USERNAME, salt, iterations, irreversible);

  // Login with sessionTag support
  unsigned long timestamp = millis();
  String loginUrl = protocol + String(HIK_IP) +
                    "/ISAPI/Security/sessionLogin?timeStamp=" + String(timestamp);

  String loginXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  loginXML += "<SessionLogin>\n";
  loginXML += "<userName>" + String(HIK_USERNAME) + "</userName>\n";
  loginXML += "<password>" + encryptedPwd + "</password>\n";
  loginXML += "<sessionID>" + sessionID + "</sessionID>\n";
  loginXML += "<isSessionIDValidLongTerm>false</isSessionIDValidLongTerm>\n";
  loginXML += "<sessionIDVersion>" + String(sessionIDVersion) + "</sessionIDVersion>\n";
  loginXML += "<isNeedSessionTag>true</isNeedSessionTag>\n";
  loginXML += "</SessionLogin>";

  http.begin(loginUrl);
  const char* headerKeys[] = {"Set-Cookie"};
  http.collectHeaders(headerKeys, 1);
  http.addHeader("Content-Type", "application/xml");
  httpCode = http.POST(loginXML);

  if (httpCode != 200) {
    http.end();
    return false;
  }

  response = http.getString();

  // Get session cookie
  if (http.hasHeader("Set-Cookie")) {
    String cookie = http.header("Set-Cookie");
    int endPos = cookie.indexOf(';');
    sessionCookie = (endPos > 0) ? cookie.substring(0, endPos) : cookie;
  }

  http.end();

  // Parse login response
  String statusValue = extractXMLTag(response, "statusValue");
  String statusString = extractXMLTag(response, "statusString");
  String sessionTagResponse = extractXMLTag(response, "sessionTag");

  if (statusValue == "200" || statusString == "OK") {
    if (sessionTagResponse.length() > 0) {
      sessionTag = sessionTagResponse;
    }

    isLoggedIn = true;
    return true;
  }
  return false;
}

/**
 * Send heartbeat to keep session alive
 */
bool sendHeartbeat() {
  if (!isLoggedIn) return false;

  HTTPClient http;
  String protocol = USE_HTTPS ? "https://" : "http://";
  String url = protocol + String(HIK_IP) + "/ISAPI/Security/sessionHeartbeat";

  http.begin(url);
  http.setTimeout(10000);
  if (sessionCookie.length() > 0) {
    http.addHeader("Cookie", sessionCookie);
  }
  // NEW: Add sessionTag header
  if (sessionTag.length() > 0) {
    http.addHeader("sessiontag", sessionTag);
  }

  int httpCode = http.sendRequest("PUT");
  http.end();

  return (httpCode == 200);
}

/**
 * Get device information
 */
void getDeviceInfo() {
  if (!isLoggedIn) {
    Serial.println("[!] Not logged in");
    return;
  }

  HTTPClient http;
  String protocol = USE_HTTPS ? "https://" : "http://";
  String url = protocol + String(HIK_IP) + "/ISAPI/System/deviceInfo";

  Serial.println("\n[*] Getting device info...");
  http.begin(url);
  http.setTimeout(10000);
  if (sessionCookie.length() > 0) {
    http.addHeader("Cookie", sessionCookie);
  }
  // NEW: Add sessionTag header
  if (sessionTag.length() > 0) {
    http.addHeader("sessiontag", sessionTag);
  }

  int httpCode = http.GET();

  if (httpCode == 200) {
    String response = http.getString();
    Serial.println("[*] Device Info (XML):");
    Serial.println(response);
  } else {
    Serial.printf("[!] Failed to get device info. HTTP code: %d\n", httpCode);
  }

  http.end();
}

/**
 * Get security capabilities
 */
void getSecurityCapabilities() {
  if (!isLoggedIn) {
    Serial.println("[!] Not logged in");
    return;
  }

  HTTPClient http;
  String protocol = USE_HTTPS ? "https://" : "http://";
  String url = protocol + String(HIK_IP) + "/ISAPI/Security/capabilities?username=" + String(HIK_USERNAME);

  Serial.println("\n[*] Getting security capabilities...");
  http.begin(url);
  http.setTimeout(10000);
  if (sessionCookie.length() > 0) {
    http.addHeader("Cookie", sessionCookie);
  }
  // NEW: Add sessionTag header
  if (sessionTag.length() > 0) {
    http.addHeader("sessiontag", sessionTag);
  }

  int httpCode = http.GET();

  if (httpCode == 200) {
    String response = http.getString();
    Serial.println("[*] Security Capabilities (XML):");
    Serial.println(response);
  } else {
    Serial.printf("[!] Failed to get security capabilities. HTTP code: %d\n", httpCode);
  }

  http.end();
}

/**
 * Fetch user list (plaintext - no encryption)
 */
void fetchUsersPlaintext(int maxResults = 10) {
  if (!isLoggedIn) {
    Serial.println("[!] Not logged in");
    return;
  }

  HTTPClient http;
  String protocol = USE_HTTPS ? "https://" : "http://";
  String url = protocol + String(HIK_IP) + "/ISAPI/AccessControl/UserInfo/Search?format=json";

  Serial.println("\n[*] Fetching users (plaintext mode)...");

  // Generate searchID (UUID format)
  String searchID = generateUUID();

  // Create JSON payload
  DynamicJsonDocument doc(1024);
  JsonObject cond = doc.createNestedObject("UserInfoSearchCond");
  cond["searchID"] = searchID;
  cond["maxResults"] = maxResults;
  cond["searchResultPosition"] = 0;

  String payload;
  serializeJson(doc, payload);

  Serial.printf("[*] Search ID: %s\n", searchID.c_str());
  Serial.printf("[*] Payload: %s\n", payload.c_str());

  http.begin(url);
  http.setTimeout(10000);
  http.addHeader("Content-Type", "application/json");
  if (sessionCookie.length() > 0) {
    http.addHeader("Cookie", sessionCookie);
  }
  // NEW: Add sessionTag header
  if (sessionTag.length() > 0) {
    http.addHeader("sessiontag", sessionTag);
  }

  int httpCode = http.POST(payload);

  if (httpCode == 200) {
    String response = http.getString();

    // Parse JSON response
    DynamicJsonDocument responseDoc(8192);
    DeserializationError error = deserializeJson(responseDoc, response);

    if (error) {
      Serial.println("[!] Failed to parse JSON response");
      Serial.println(response);
      http.end();
      return;
    }

    JsonObject userSearch = responseDoc["UserInfoSearch"];
    int numMatches = userSearch["numOfMatches"] | 0;
    int totalMatches = userSearch["totalMatches"] | 0;

    Serial.printf("[*] Found %d users (total: %d)\n", numMatches, totalMatches);

    JsonArray users = userSearch["UserInfo"];
    int count = 0;
    for (JsonObject user : users) {
      count++;
      Serial.printf("\n  User %d:\n", count);

      if (user.containsKey("employeeNo")) {
        Serial.printf("    Employee No: %s\n", user["employeeNo"].as<const char*>());
      }
      if (user.containsKey("name")) {
        Serial.printf("    Name: %s\n", user["name"].as<const char*>());
      }
      if (user.containsKey("userType")) {
        Serial.printf("    Type: %s\n", user["userType"].as<const char*>());
      }
      if (user.containsKey("numOfFace")) {
        Serial.printf("    Faces: %d\n", user["numOfFace"].as<int>());
      }
      if (user.containsKey("numOfFP")) {
        Serial.printf("    Fingerprints: %d\n", user["numOfFP"].as<int>());
      }
      if (user.containsKey("numOfCard")) {
        Serial.printf("    Cards: %d\n", user["numOfCard"].as<int>());
      }
    }

    // Print full JSON
    Serial.println("\n[*] Full JSON Response:");
    serializeJsonPretty(responseDoc, Serial);
    Serial.println();

  } else {
    Serial.printf("[!] Failed to fetch users. HTTP code: %d\n", httpCode);
    String response = http.getString();
    Serial.println(response);
  }

  http.end();
}

/**
 * Fetch user list (with encryption security=1)
 */
void fetchUsers(int maxResults = 10) {
  if (!isLoggedIn) {
    Serial.println("[!] Not logged in");
    return;
  }

  HTTPClient http;
  String protocol = USE_HTTPS ? "https://" : "http://";

  // Generate random IV (16 bytes = 32 hex characters)
  String iv = randomHex(16);

  // Build URL with security parameters
  String url = protocol + String(HIK_IP) +
               "/ISAPI/AccessControl/UserInfo/Search?format=json&security=1&iv=" + iv;

  Serial.println("\n[*] Fetching users (encrypted mode)...");
  Serial.printf("[*] Using security=1 with IV: %s\n", iv.c_str());

  // Generate searchID (UUID format)
  String searchID = generateUUID();

  // Create JSON payload
  DynamicJsonDocument doc(1024);
  JsonObject cond = doc.createNestedObject("UserInfoSearchCond");
  cond["searchID"] = searchID;
  cond["maxResults"] = maxResults;
  cond["searchResultPosition"] = 0;

  String payload;
  serializeJson(doc, payload);

  Serial.printf("[*] Search ID: %s\n", searchID.c_str());
  Serial.printf("[*] Payload: %s\n", payload.c_str());

  http.begin(url);
  http.setTimeout(10000);
  http.addHeader("Content-Type", "application/json");
  if (sessionCookie.length() > 0) {
    http.addHeader("Cookie", sessionCookie);
  }
  // NEW: Add sessionTag header
  if (sessionTag.length() > 0) {
    http.addHeader("sessiontag", sessionTag);
  }

  int httpCode = http.POST(payload);

  if (httpCode == 200) {
    String response = http.getString();

    // Parse JSON response
    DynamicJsonDocument responseDoc(8192);
    DeserializationError error = deserializeJson(responseDoc, response);

    if (error) {
      Serial.println("[!] Failed to parse JSON response");
      Serial.println(response);
      http.end();
      return;
    }

    JsonObject userSearch = responseDoc["UserInfoSearch"];
    int numMatches = userSearch["numOfMatches"] | 0;
    int totalMatches = userSearch["totalMatches"] | 0;

    Serial.printf("[*] Found %d users (total: %d)\n", numMatches, totalMatches);

    JsonArray users = userSearch["UserInfo"];
    int count = 0;
    for (JsonObject user : users) {
      count++;
      Serial.printf("\n  User %d:\n", count);

      if (user.containsKey("employeeNo")) {
        Serial.printf("    Employee No (encrypted): %s\n", user["employeeNo"].as<const char*>());
      }
      if (user.containsKey("name")) {
        Serial.printf("    Name (encrypted): %s\n", user["name"].as<const char*>());
      }
      if (user.containsKey("userType")) {
        Serial.printf("    Type: %s\n", user["userType"].as<const char*>());
      }
      if (user.containsKey("numOfFace")) {
        Serial.printf("    Faces: %d\n", user["numOfFace"].as<int>());
      }
      if (user.containsKey("numOfFP")) {
        Serial.printf("    Fingerprints: %d\n", user["numOfFP"].as<int>());
      }
      if (user.containsKey("numOfCard")) {
        Serial.printf("    Cards: %d\n", user["numOfCard"].as<int>());
      }
    }

    // Print full JSON
    Serial.println("\n[*] Full JSON Response:");
    serializeJsonPretty(responseDoc, Serial);
    Serial.println();

  } else {
    Serial.printf("[!] Failed to fetch users. HTTP code: %d\n", httpCode);
    String response = http.getString();
    Serial.println(response);
  }

  http.end();
}

/**
 * Fetch access control events (attendance records)
 */
void fetchEvents(int maxResults = 10, String startTime = "", String endTime = "") {
  if (!isLoggedIn) {
    Serial.println("[!] Not logged in");
    return;
  }

  // Set default time range if not provided (today)
  if (startTime.length() == 0) {
    startTime = getISOTimestamp(0, 0, 0);
    // Set to start of day
    startTime.replace(startTime.substring(11, 19), "00:00:00");
  }
  if (endTime.length() == 0) {
    endTime = getISOTimestamp(0, 0, 0);
    // Set to end of day
    endTime.replace(endTime.substring(11, 19), "23:59:59");
  }

  HTTPClient http;
  String protocol = USE_HTTPS ? "https://" : "http://";
  String url = protocol + String(HIK_IP) + "/ISAPI/AccessControl/AcsEvent?format=json";

  Serial.println("\n[*] Fetching access control events...");
  Serial.println("[*] Fetching events without encryption...");
  Serial.printf("[*] Time range: %s to %s\n", startTime.c_str(), endTime.c_str());

  // Create JSON payload
  DynamicJsonDocument doc(1024);
  JsonObject cond = doc.createNestedObject("AcsEventCond");
  cond["searchID"] = generateUUID();
  cond["searchResultPosition"] = 0;
  cond["maxResults"] = maxResults;
  cond["major"] = 0;
  cond["minor"] = 0;
  cond["startTime"] = startTime;
  cond["endTime"] = endTime;

  String payload;
  serializeJson(doc, payload);

  Serial.println("[*] Payload:");
  Serial.println(payload);

  http.begin(url);
  http.setTimeout(10000);
  http.addHeader("Content-Type", "application/json");
  if (sessionCookie.length() > 0) {
    http.addHeader("Cookie", sessionCookie);
  }
  // NEW: Add sessionTag header
  if (sessionTag.length() > 0) {
    http.addHeader("sessiontag", sessionTag);
  }

  int httpCode = http.POST(payload);

  if (httpCode == 200) {
    String response = http.getString();

    // Parse JSON response
    DynamicJsonDocument responseDoc(16384);
    DeserializationError error = deserializeJson(responseDoc, response);

    if (error) {
      Serial.println("[!] Failed to parse JSON response");
      Serial.println(response);
      http.end();
      return;
    }

    JsonObject acsEvent = responseDoc["AcsEvent"];
    int numMatches = acsEvent["numOfMatches"] | 0;
    int totalMatches = acsEvent["totalMatches"] | 0;

    Serial.printf("[*] Found %d events (total: %d)\n", numMatches, totalMatches);

    JsonArray events = acsEvent["InfoList"];
    int count = 0;
    for (JsonObject event : events) {
      count++;
      if (count > 5) {
        Serial.printf("\n  ... and %d more events\n", numMatches - 5);
        break;
      }

      Serial.printf("\n  Event %d:\n", count);

      if (event.containsKey("time")) {
        Serial.printf("    Time: %s\n", event["time"].as<const char*>());
      }
      if (event.containsKey("employeeNoString")) {
        Serial.printf("    Employee: %s\n", event["employeeNoString"].as<const char*>());
      }
      if (event.containsKey("name")) {
        Serial.printf("    Name: %s\n", event["name"].as<const char*>());
      }
      if (event.containsKey("doorNo")) {
        Serial.printf("    Door: %d\n", event["doorNo"].as<int>());
      }
      if (event.containsKey("attendanceStatus")) {
        Serial.printf("    Status: %s\n", event["attendanceStatus"].as<const char*>());
      }
      if (event.containsKey("currentVerifyMode")) {
        Serial.printf("    Verify Mode: %s\n", event["currentVerifyMode"].as<const char*>());
      }
    }

    // Print full JSON
    Serial.println("\n[*] Full JSON Response:");
    serializeJsonPretty(responseDoc, Serial);
    Serial.println();

  } else {
    Serial.printf("[!] Failed to fetch events. HTTP code: %d\n", httpCode);
    String response = http.getString();
    Serial.println(response);
  }

  http.end();
}

/**
 * Increment time string by 1 second to avoid re-fetching same event
 * Input format: "2026-01-28T12:34:56+08:00"
 */
String incrementTime(const String& timeStr) {
  // Simple approach: just replace the last digit of seconds
  // For a more robust solution, proper time parsing would be needed
  if (timeStr.length() < 19) return timeStr;

  // Extract seconds and increment
  int seconds = timeStr.substring(17, 19).toInt();
  seconds++;

  // Handle overflow (simple - just cap at 59)
  if (seconds > 59) seconds = 59;

  char newTime[30];
  snprintf(newTime, sizeof(newTime), "%s%02d%s",
           timeStr.substring(0, 17).c_str(),
           seconds,
           timeStr.substring(19).c_str());

  return String(newTime);
}

/**
 * Fetch attendance events with specific format
 * Uses dynamic start time tracking to avoid re-processing events
 */
void fetchAttendanceEvents(int maxResults = 5) {
  if (!isLoggedIn) {
    Serial.println("[!] Not logged in");
    return;
  }

  HTTPClient http;
  String protocol = USE_HTTPS ? "https://" : "http://";

  // Generate random IV
  String iv = randomHex(16);

  // Build URL
  String url = protocol + String(HIK_IP) +
               "/ISAPI/AccessControl/AcsEvent?format=json&security=0&iv=" + iv;

  // Verify time is valid before proceeding
  time_t now = time(nullptr);
  if (now < 1000000000) {
    Serial.println("[!] Time not synced, skipping event fetch");
    return;
  }

  // Initialize lastEventTime if empty (start of today)
  if (lastEventTime.length() == 0 || lastEventTime.startsWith("1970")) {
    struct tm timeinfo;
    localtime_r(&now, &timeinfo);
    char buffer[30];
    sprintf(buffer, "%04d-%02d-%02dT00:00:00+08:00",
            timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday);
    lastEventTime = String(buffer);
    Serial.printf("[*] Initialized start time: %s\n", lastEventTime.c_str());
  }

  // End time is 3 hours in the future (ensures all events are captured)
  struct tm timeinfo;
  localtime_r(&now, &timeinfo);
  timeinfo.tm_hour += 24;  // Add 3 hours
  mktime(&timeinfo);      // Normalize (handles day overflow)
  char endBuffer[30];
  sprintf(endBuffer, "%04d-%02d-%02dT%02d:%02d:%02d+08:00",
          timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
          timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
  String endTime = String(endBuffer);

  Serial.printf("[*] Fetching events from: %s to: %s\n", lastEventTime.c_str(), endTime.c_str());

  // Create JSON payload - oldest first (timeReverseOrder = false)
  DynamicJsonDocument doc(1024);
  JsonObject cond = doc.createNestedObject("AcsEventCond");
  cond["searchID"] = generateUUID();
  cond["searchResultPosition"] = 0;
  cond["maxResults"] = maxResults;
  cond["major"] = 0;
  cond["minor"] = 0;
  cond["startTime"] = lastEventTime;
  cond["endTime"] = endTime;
  cond["timeReverseOrder"] = false;  // Oldest first for sequential processing

  String payload;
  serializeJson(doc, payload);

  http.begin(url);
  http.setTimeout(15000);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Accept", "application/json");

  // Add session authentication
  if (sessionCookie.length() > 0) {
    http.addHeader("Cookie", sessionCookie);
  }
  if (sessionTag.length() > 0) {
    http.addHeader("sessiontag", sessionTag);
  }

  int httpCode = http.POST(payload);

  if (httpCode == 200) {
    String response = http.getString();

    // Parse JSON response
    DynamicJsonDocument responseDoc(16384);
    DeserializationError error = deserializeJson(responseDoc, response);

    if (error) {
      Serial.printf("[!] JSON parse error: %s\n", error.c_str());
      http.end();
      return;
    }

    JsonObject acsEvent = responseDoc["AcsEvent"];
    int numMatches = acsEvent["numOfMatches"] | 0;
    int totalMatches = acsEvent["totalMatches"] | 0;
    Serial.println("----------------------------------------");

    JsonArray events = acsEvent["InfoList"];
    int sent = 0;

    for (JsonObject event : events) {
      const char* eventTime = event["time"] | "";
      const char* employeeNo = event["employeeNoString"] | "";

      // If no employee number, update start time and skip
      if (strlen(employeeNo) == 0) {
        if (strlen(eventTime) > 0) {
          lastEventTime = incrementTime(String(eventTime));
          Serial.printf("[*] Skipped event (no employee), new start: %s\n", lastEventTime.c_str());
        }
        continue;
      }

      // Extract event data
      const char* name = event["name"] | "";
      int doorNo = event["doorNo"] | 0;
      const char* attendanceStatus = event["attendanceStatus"] | "";
      const char* verifyMode = event["currentVerifyMode"] | "";

      Serial.printf("[*] %s - %s (%s)\n", eventTime, name, employeeNo);

      // Send event to tracker server
      if (sendEventToServer(employeeNo, name, eventTime, doorNo, attendanceStatus, verifyMode)) {
        sent++;
        // Update start time to avoid re-fetching this event
        lastEventTime = incrementTime(String(eventTime));
        Serial.printf("[+] Sent OK, new start: %s\n", lastEventTime.c_str());
      } else {
        Serial.println("[!] Send failed, will retry next cycle");
        // Don't update lastEventTime so we retry this event
        break;
      }

      delay(100);
    }

    if (sent > 0 || numMatches > 0) {
      Serial.printf("[*] Processed: %d sent, %d total\n", sent, numMatches);
    }

  } else {
    Serial.printf("[!] Failed to fetch events. HTTP code: %d\n", httpCode);
    String response = http.getString();
    Serial.println("[!] Response:");
    Serial.println(response);
  }

  http.end();
}

// ======================== OTA FIRMWARE UPDATE ========================

/**
 * Compare two version strings (e.g., "1.0.0" vs "1.0.1")
 * Returns: 1 if remote > local, 0 if equal, -1 if remote < local
 */
int compareVersions(const String& local, const String& remote) {
  int lMajor = 0, lMinor = 0, lPatch = 0;
  int rMajor = 0, rMinor = 0, rPatch = 0;

  sscanf(local.c_str(), "%d.%d.%d", &lMajor, &lMinor, &lPatch);
  sscanf(remote.c_str(), "%d.%d.%d", &rMajor, &rMinor, &rPatch);

  if (rMajor != lMajor) return (rMajor > lMajor) ? 1 : -1;
  if (rMinor != lMinor) return (rMinor > lMinor) ? 1 : -1;
  if (rPatch != lPatch) return (rPatch > lPatch) ? 1 : -1;
  return 0;
}

/**
 * Check server for new firmware version and perform OTA update if available
 */
void checkForOTAUpdate() {
  if (WiFi.status() != WL_CONNECTED) return;

  Serial.println("\n[OTA] Checking for firmware update...");
  Serial.printf("[OTA] Current version: %s\n", FIRMWARE_VERSION);

  HTTPClient http;
  http.begin(OTA_VERSION_URL);
  http.setTimeout(10000);
  int httpCode = http.GET();

  if (httpCode != 200) {
    Serial.printf("[OTA] Version check failed, HTTP code: %d\n", httpCode);
    http.end();
    return;
  }

  String response = http.getString();
  http.end();
  response.trim();

  Serial.printf("[OTA] Server version: %s\n", response.c_str());

  if (compareVersions(FIRMWARE_VERSION, response) <= 0) {
    Serial.println("[OTA] Firmware is up to date");
    return;
  }

  Serial.println("[OTA] New firmware available! Starting update...");
  Serial.printf("[OTA] Downloading from: %s\n", OTA_FIRMWARE_URL);

  WiFiClient otaClient;
  httpUpdate.setLedPin(LED_BUILTIN, LOW);

  t_httpUpdate_return ret = httpUpdate.update(otaClient, OTA_FIRMWARE_URL);

  switch (ret) {
    case HTTP_UPDATE_FAILED:
      Serial.printf("[OTA] Update failed: %s (%d)\n",
                    httpUpdate.getLastErrorString().c_str(),
                    httpUpdate.getLastError());
      break;
    case HTTP_UPDATE_NO_UPDATES:
      Serial.println("[OTA] No update available");
      break;
    case HTTP_UPDATE_OK:
      Serial.println("[OTA] Update successful! Rebooting...");
      // ESP32 will reboot automatically after successful update
      break;
  }
}

// ======================== AUTO-RESTART WATCHDOG ========================

/**
 * Restart ESP32 with a reason logged to Serial
 */
void restartESP(const char* reason) {
  Serial.println("\n========================================");
  Serial.printf("[!!!] AUTO-RESTART: %s\n", reason);
  Serial.println("========================================\n");
  Serial.flush();
  delay(1000);
  ESP.restart();
}

/**
 * Check all restart conditions and reboot if any are met:
 * 1. Uptime exceeds RESTART_AFTER_UPTIME (4 hours)
 * 2. WiFi has been disconnected for RESTART_WIFI_FAIL_MS (20 min)
 * 3. Hikvision device unreachable for RESTART_HIK_FAIL_MS (20 min)
 */
void checkAutoRestart() {
  unsigned long now = millis();

  // 1. Scheduled restart after max uptime
  if (now >= RESTART_AFTER_UPTIME) {
    restartESP("Max uptime reached (4 hours), performing scheduled restart");
  }

  // 2. WiFi failure watchdog
  if (WiFi.status() != WL_CONNECTED) {
    if (wifiFailSince == 0) {
      wifiFailSince = now;
      Serial.printf("[!] WiFi failure detected, watchdog started (%lu min timeout)\n",
                    RESTART_WIFI_FAIL_MS / 60000);
    } else if (now - wifiFailSince >= RESTART_WIFI_FAIL_MS) {
      restartESP("WiFi disconnected for 20+ minutes");
    }
  } else {
    // WiFi is connected, reset the failure tracker
    if (wifiFailSince != 0) {
      Serial.println("[*] WiFi recovered, watchdog reset");
    }
    wifiFailSince = 0;
  }

  // 3. Hikvision connection failure watchdog
  if (!isLoggedIn) {
    if (hikFailSince == 0) {
      hikFailSince = now;
      Serial.printf("[!] Hik connection failure detected, watchdog started (%lu min timeout)\n",
                    RESTART_HIK_FAIL_MS / 60000);
    } else if (now - hikFailSince >= RESTART_HIK_FAIL_MS) {
      restartESP("Hikvision device unreachable for 20+ minutes");
    }
  } else {
    // Hik is connected, reset the failure tracker
    if (hikFailSince != 0) {
      Serial.println("[*] Hik connection recovered, watchdog reset");
    }
    hikFailSince = 0;
  }
}

// ======================== ARDUINO FUNCTIONS ========================

// Forward declaration
void initiateValues(bool isReconnect = false);

void setup() {
  Serial.begin(115200);
  delay(2000);
  deviceId = getDeviceId();
   Serial.println("device Id is = ");
    Serial.print(deviceId);

  Serial.println("\n[*] Hikvision ESP32 Client V2");
  Serial.printf("[*] Firmware version: %s\n", FIRMWARE_VERSION);

  // Connect to WiFi
  if (!connectWiFi(false)) {
    return;
  }

  // Check for OTA update before proceeding
  checkForOTAUpdate();
  lastOTACheck = millis();

  // Get device ID
  initiateValues();
}

void initiateValues(bool isReconnect){
  // Only get device ID on first run (it never changes)
  if (!isReconnect) {
    deviceId = getDeviceId();
    Serial.printf("[*] Device ID: %s\n", deviceId.c_str());
  }

  // Sync time via NTP - REQUIRED for proper operation
  // Timezone +08:00 (8 hours * 3600 seconds) to match Hikvision device
  Serial.print("[*] NTP sync...");
  configTime(3 * 3600, 0, "pool.ntp.org", "time.nist.gov", "time.google.com");

  int ntpRetries = 0;
  while (time(nullptr) < 1000000000 && ntpRetries < 60) {  // Wait up to 30 seconds
    delay(500);
    Serial.print(".");
    ntpRetries++;
  }

  if (time(nullptr) > 1000000000) {
    time_t now = time(nullptr);
    Serial.printf(" OK (%s", ctime(&now));

    // Only fetch lastEventTime from server on initial setup
    // On reconnect, keep the existing lastEventTime to avoid re-processing events
    if (!isReconnect) {
      lastEventTime = getLastTimeFromServer();

      // If server didn't return a valid time, fall back to start of today
      if (lastEventTime.length() == 0 || lastEventTime.startsWith("1970")) {
        struct tm timeinfo;
        localtime_r(&now, &timeinfo);
        char buffer[30];
        sprintf(buffer, "%04d-%02d-%02dT00:00:00+08:00",
                timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday);
        lastEventTime = String(buffer);
        Serial.printf("[*] Using default start time: %s\n", lastEventTime.c_str());
      } else {
        Serial.printf("[*] Resuming from server time: %s\n", lastEventTime.c_str());
      }

      randomSeed(analogRead(0));
    }
  } else {
    Serial.println(" FAILED");
    if (isReconnect) {
      // On reconnect, don't halt - just warn and continue (time might still be valid)
      Serial.println("[!] NTP sync failed, continuing with cached time...");
    } else {
      // On initial setup, halt - we can't proceed without time
      Serial.println("[!] Cannot proceed without time sync!");
      Serial.println("[!] Please check internet connection and restart");
      while(1) { delay(1000); }
    }
  }

  // Login to Hikvision device
  Serial.print("[*] Logging into Hikvision...");
  if (!hikvisionLogin()) {
    Serial.println(" FAILED");
    return;
  }
  Serial.println(" OK");

  // Only test server connectivity on initial setup
  if (!isReconnect) {
    UrlParts server = parseUrl(String(TRACKER_SERVER));
    Serial.printf("[*] Testing connection to %s:%d...\n", server.host.c_str(), server.port);
    WiFiClient testClient;
    if (testClient.connect(server.host.c_str(), server.port)) {
      Serial.println("[+] Server reachable!");
      testClient.stop();
    } else {
      Serial.println("[!] Cannot reach server - check firewall/network");
    }
  }

  // Fetch events
  fetchAttendanceEvents(5);
}

void loop() {
  unsigned long currentMillis = millis();

  // Check auto-restart conditions every loop iteration
  checkAutoRestart();

  // Periodic OTA update check
  if (currentMillis - lastOTACheck >= OTA_CHECK_INTERVAL) {
    checkForOTAUpdate();
    lastOTACheck = currentMillis;
  }

  // Check every 5 seconds
  if (currentMillis - lastHeartbeat >= 5000) {

    // First check WiFi connectivity
    if (WiFi.status() != WL_CONNECTED) {
      if (!connectWiFi(true)) {
        lastHeartbeat = currentMillis;
        delay(1000);
        return;
      } else {
        initiateValues(true);  // true = reconnect mode
      }
    }

    // WiFi is connected, proceed with heartbeat
    if (sendHeartbeat()) {
      // Fetch attendance events on successful heartbeat
      fetchAttendanceEvents(5);
    } else {
      Serial.println("[!] Heartbeat failed, re-logging...");

      // Reset login state
      isLoggedIn = false;
      sessionCookie = "";
      sessionTag = "";

      // Keep trying to login until successful
      while (!isLoggedIn) {
        // Check WiFi before attempting login
        if (WiFi.status() != WL_CONNECTED) {
          Serial.println("[!] WiFi lost during login, breaking...");
          break;
        }

        if (hikvisionLogin()) {
          Serial.println("[+] Re-login OK");
          fetchAttendanceEvents(5);
        } else {
          Serial.println("[!] Login failed, retry in 10s...");
          delay(10000);
        }
      }
    }
    lastHeartbeat = currentMillis;
  }

  delay(1000);
}
