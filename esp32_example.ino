/**
 * Hikvision Client for ESP32
 *
 * Full-featured client matching hikvision_client.py functionality
 *
 * Features:
 * - Encrypted session login
 * - Fetch device information
 * - Fetch user list (plaintext)
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
#include <ArduinoJson.h>
#include "mbedtls/md.h"

// ======================== CONFIGURATION ========================

// WiFi credentials
const char* WIFI_SSID = "Guest";
const char* WIFI_PASSWORD = "billionaires@2024";

// Hikvision device credentials
const char* HIK_IP = "102.217.127.12";
const char* HIK_USERNAME = "admin";
const char* HIK_PASSWORD = "dev@spa!";
const bool USE_HTTPS = false;

static unsigned long lastHeartbeat = 0;

// ======================== GLOBAL VARIABLES ========================

String sessionCookie = "";
String aesKey = "";
bool isLoggedIn = false;

// ======================== HELPER FUNCTIONS ========================

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
  gmtime_r(&now, &timeinfo);

  timeinfo.tm_hour += hourOffset;
  timeinfo.tm_min += minuteOffset;
  timeinfo.tm_sec += secondOffset;
  mktime(&timeinfo);

  char buffer[30];
  sprintf(buffer, "%04d-%02d-%02dT%02d:%02d:%02d+03:00",
          timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
          timeinfo.tm_hour + 3, timeinfo.tm_min, timeinfo.tm_sec);
  return String(buffer);
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
 * Login to Hikvision device
 */
bool hikvisionLogin() {
  HTTPClient http;

  Serial.println("\n[*] Connecting to Hikvision device...");
  Serial.printf("[*] IP: %s\n", HIK_IP);

  // Step 1: Get session capabilities
  Serial.println("[*] Step 1: Getting session capabilities...");

  String protocol = USE_HTTPS ? "https://" : "http://";
  String capUrl = protocol + String(HIK_IP) +
                  "/ISAPI/Security/sessionLogin/capabilities?username=" +
                  String(HIK_USERNAME);

  http.begin(capUrl);
  http.setTimeout(10000);
  int httpCode = http.GET();

  if (httpCode != 200) {
    Serial.printf("[!] Failed to get capabilities. HTTP code: %d\n", httpCode);
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

  if (sessionID.length() == 0 || challenge.length() == 0) {
    Serial.println("[!] Failed to parse capabilities");
    return false;
  }

  int iterations = iterationsStr.toInt();
  bool irreversible = irreversibleStr.equalsIgnoreCase("true");

  Serial.printf("    Session ID: %s...\n", sessionID.substring(0, 32).c_str());
  Serial.printf("    Challenge: %s\n", challenge.c_str());
  Serial.printf("    Iterations: %d\n", iterations);
  Serial.printf("    Salt: %s...\n", salt.substring(0, 32).c_str());
  Serial.printf("    Irreversible: %s\n", irreversible ? "true" : "false");

  // Step 2: Encrypt password
  Serial.println("[*] Step 2: Encrypting password...");
  String encryptedPwd = encryptPassword(HIK_PASSWORD, HIK_USERNAME,
                                        challenge, salt, iterations, irreversible);
  Serial.printf("    Encrypted password: %s...\n", encryptedPwd.substring(0, 32).c_str());

  // Step 3: Derive AES key
  Serial.println("[*] Step 3: Deriving AES key...");
  aesKey = deriveAESKey(HIK_PASSWORD, HIK_USERNAME, salt, iterations, irreversible);
  Serial.printf("    AES Key: %s\n", aesKey.c_str());

  // Step 4: Login
  Serial.println("[*] Step 4: Performing login...");
  unsigned long timestamp = millis();
  int randomNum = random(100000000);

  String loginUrl = protocol + String(HIK_IP) +
                    "/ISAPI/Security/sessionLogin?timeStamp=" +
                    String(timestamp) + "&random=" + String(randomNum);

  String loginXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  loginXML += "<SessionLogin>\n";
  loginXML += "    <userName>" + String(HIK_USERNAME) + "</userName>\n";
  loginXML += "    <password>" + encryptedPwd + "</password>\n";
  loginXML += "    <sessionID>" + sessionID + "</sessionID>\n";
  loginXML += "    <isSessionIDValidLongTerm>false</isSessionIDValidLongTerm>\n";
  loginXML += "    <sessionIDVersion>2</sessionIDVersion>\n";
  loginXML += "</SessionLogin>";

  http.begin(loginUrl);
  http.addHeader("Content-Type", "application/xml");
  httpCode = http.POST(loginXML);

  if (httpCode != 200) {
    Serial.printf("[!] Login failed. HTTP code: %d\n", httpCode);
    response = http.getString();
    Serial.println(response);
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

  // Check if login was successful
  if (response.indexOf("statusValue>200") >= 0 || response.indexOf("statusString>OK") >= 0) {
    Serial.println("[+] Login successful!");
    isLoggedIn = true;
    return true;
  } else {
    Serial.println("[!] Login failed!");
    Serial.println(response);
    return false;
  }
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
 * Fetch user list
 */
void fetchUsers(int maxResults = 10) {
  if (!isLoggedIn) {
    Serial.println("[!] Not logged in");
    return;
  }

  HTTPClient http;
  String protocol = USE_HTTPS ? "https://" : "http://";
  String url = protocol + String(HIK_IP) + "/ISAPI/AccessControl/UserInfo/Search?format=json";

  Serial.println("\n[*] Fetching users...");
  Serial.println("[*] Fetching users without encryption...");

  // Create JSON payload
  DynamicJsonDocument doc(1024);
  JsonObject cond = doc.createNestedObject("UserInfoSearchCond");
  cond["searchID"] = generateUUID();
  cond["maxResults"] = maxResults;
  cond["searchResultPosition"] = 0;

  String payload;
  serializeJson(doc, payload);

  http.begin(url);
  http.setTimeout(10000);
  http.addHeader("Content-Type", "application/json");
  if (sessionCookie.length() > 0) {
    http.addHeader("Cookie", sessionCookie);
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

// ======================== ARDUINO FUNCTIONS ========================

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("\n\n========================================");
  Serial.println("   Hikvision ESP32 Client");
  Serial.println("========================================\n");

  // Scan for WiFi networks first
  Serial.println("[*] Scanning for WiFi networks...");
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  int n = WiFi.scanNetworks();
  Serial.printf("[*] Found %d networks:\n", n);
  for (int i = 0; i < n; i++) {
    Serial.printf("    %d: %s (RSSI: %d dBm, Ch: %d) %s\n",
                  i + 1,
                  WiFi.SSID(i).c_str(),
                  WiFi.RSSI(i),
                  WiFi.channel(i),
                  WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "[OPEN]" : "[SECURED]");
  }
  Serial.println();

  // Connect to WiFi
  Serial.println("[*] Connecting to WiFi...");
  Serial.printf("[*] SSID: '%s'\n", WIFI_SSID);
  Serial.printf("[*] Password length: %d characters\n", strlen(WIFI_PASSWORD));

  // Disconnect if previously connected
  WiFi.disconnect(true);
  delay(1000);

  // Set WiFi mode
  WiFi.mode(WIFI_STA);
  delay(100);

  // Start connection
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.println("[*] Attempting to connect...");

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40) {
    delay(500);
    Serial.print(".");
    attempts++;

    // Print status every 10 attempts
    if (attempts % 10 == 0) {
      Serial.printf("\n[*] Status: %d (Attempts: %d/40)\n", WiFi.status(), attempts);
    }
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\n[!] Failed to connect to WiFi");
    Serial.printf("[!] Final status code: %d\n", WiFi.status());
    Serial.println("\n[!] Troubleshooting steps:");
    Serial.println("    1. Check SSID is correct (case-sensitive)");
    Serial.println("    2. Check password is correct");
    Serial.println("    3. Ensure WiFi is 2.4GHz (ESP32 doesn't support 5GHz)");
    Serial.println("    4. Move ESP32 closer to router");
    Serial.println("    5. Check if special characters in password need escaping");
    Serial.println("\n[!] WiFi Status Codes:");
    Serial.println("    0 = WL_IDLE_STATUS");
    Serial.println("    1 = WL_NO_SSID_AVAIL (SSID not found)");
    Serial.println("    3 = WL_CONNECTED");
    Serial.println("    4 = WL_CONNECT_FAILED");
    Serial.println("    6 = WL_DISCONNECTED");
    return;
  }

  Serial.println("\n[+] WiFi connected!");
  Serial.print("[*] IP address: ");
  Serial.println(WiFi.localIP());
  Serial.print("[*] Signal strength (RSSI): ");
  Serial.print(WiFi.RSSI());
  Serial.println(" dBm");

  // Initialize random seed
  randomSeed(analogRead(0));

  // Login to Hikvision device
  if (!hikvisionLogin()) {
    Serial.println("\n[!] Failed to login to Hikvision device");
    Serial.println("[!] Please check your device credentials");
    return;
  }

  // Demonstrate all features
  Serial.println("\n========================================");
  Serial.println("   Running Demonstrations");
  Serial.println("========================================");

  // 1. Get device info
  getDeviceInfo();
  delay(1000);

  // 2. Fetch users
  fetchUsers(5);
  delay(1000);

  // 3. Fetch today's events
  fetchEvents(10);
  delay(1000);

  Serial.println("\n========================================");
  Serial.println("   Demo Complete - Entering Loop");
  Serial.println("========================================\n");
}

void loop() {
  // Send heartbeat every 60 seconds to keep session alive

  unsigned long currentMillis = millis();

  if (currentMillis - lastHeartbeat >= 60000) {
    if (sendHeartbeat()) {
      Serial.println("[*] Heartbeat sent successfully");
    } else {
      Serial.println("[!] Heartbeat failed - may need to re-login");
    }
    lastHeartbeat = currentMillis;
  }

  delay(1000);
}
