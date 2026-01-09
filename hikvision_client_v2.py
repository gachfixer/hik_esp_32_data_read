#!/usr/bin/env python3
"""
Hikvision Device Client V2
Authenticates with Hikvision devices using sessionTag (sessionIDVersion 2)
"""

import hashlib
import secrets
import time
import uuid
import re
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import requests
from xml.etree import ElementTree as ET


class HikvisionClientV2:
    def __init__(self, ip, username, password, use_https=False):
        """
        Initialize Hikvision client V2 with sessionTag support

        Args:
            ip: Device IP address
            username: Login username (usually 'admin')
            password: Login password
            use_https: Use HTTPS instead of HTTP (recommended for production)
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.protocol = "https" if use_https else "http"
        self.session = requests.Session()
        self.aes_key = None
        self.session_id = None
        self.session_tag = None  # NEW: Store sessionTag

        # Disable SSL warnings if using HTTPS with self-signed cert
        if use_https:
            requests.packages.urllib3.disable_warnings()
            self.session.verify = False

    def login(self):
        """
        Perform login to Hikvision device with sessionTag support

        Returns:
            bool: True if login successful, False otherwise
        """
        print(f"[*] Connecting to {self.protocol}://{self.ip}")

        # Step 1: Get session capabilities with random parameter
        print("[*] Step 1: Getting session capabilities...")
        random_num = secrets.randbelow(100000000)
        url = f"{self.protocol}://{self.ip}/ISAPI/Security/sessionLogin/capabilities?username={self.username}&random={random_num}"

        try:
            resp = self.session.get(url, timeout=10)
            resp.raise_for_status()
        except Exception as e:
            print(f"[!] Error getting capabilities: {e}")
            return False

        # Parse XML response
        try:
            root = ET.fromstring(resp.text)
            ns = {'ns': 'http://www.isapi.org/ver20/XMLSchema'}

            session_id = root.find('.//ns:sessionID', ns)
            challenge = root.find('.//ns:challenge', ns)
            iterations = root.find('.//ns:iterations', ns)
            salt = root.find('.//ns:salt', ns)
            is_irreversible = root.find('.//ns:isIrreversible', ns)
            is_support_session_tag = root.find('.//ns:isSupportSessionTag', ns)
            session_id_version = root.find('.//ns:sessionIDVersion', ns)

            if any(x is None for x in [session_id, challenge, iterations, salt, is_irreversible]):
                print("[!] Failed to parse capabilities response")
                return False

            session_id = session_id.text
            challenge = challenge.text
            iterations = int(iterations.text)
            salt = salt.text
            is_irreversible = is_irreversible.text.lower() == 'true'
            supports_session_tag = is_support_session_tag.text.lower() == 'true' if is_support_session_tag is not None else False
            session_id_ver = int(session_id_version.text) if session_id_version is not None else 1

            print(f"    Session ID: {session_id[:32]}...")
            print(f"    Challenge: {challenge}")
            print(f"    Iterations: {iterations}")
            print(f"    Salt: {salt[:32]}...")
            print(f"    Irreversible: {is_irreversible}")
            print(f"    Supports SessionTag: {supports_session_tag}")
            print(f"    SessionID Version: {session_id_ver}")

        except Exception as e:
            print(f"[!] Error parsing capabilities: {e}")
            print(f"[!] Response: {resp.text}")
            return False

        # Step 2: Calculate encrypted password
        print("[*] Step 2: Encrypting password...")
        encrypted_pwd = self._encrypt_password(
            self.password, self.username, challenge, salt, iterations, is_irreversible
        )
        print(f"    Encrypted password: {encrypted_pwd[:32]}...")

        # Calculate AES key for later use
        print("[*] Step 3: Deriving AES key...")
        self.aes_key = self._derive_aes_key(self.password, self.username, salt, iterations, is_irreversible)
        print(f"    AES Key: {self.aes_key}")

        # Step 4: Login with sessionTag support
        print("[*] Step 4: Performing login with sessionTag support...")
        timestamp = int(time.time() * 1000)
        login_url = f"{self.protocol}://{self.ip}/ISAPI/Security/sessionLogin?timeStamp={timestamp}"

        # NEW: Include isNeedSessionTag and sessionIDVersion
        login_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<SessionLogin>
    <userName>{self.username}</userName>
    <password>{encrypted_pwd}</password>
    <sessionID>{session_id}</sessionID>
    <isSessionIDValidLongTerm>false</isSessionIDValidLongTerm>
    <sessionIDVersion>{session_id_ver}</sessionIDVersion>
    <isNeedSessionTag>true</isNeedSessionTag>
</SessionLogin>"""

        try:
            resp = self.session.post(login_url, data=login_xml, timeout=10)
            resp.raise_for_status()
        except Exception as e:
            print(f"[!] Error during login: {e}")
            return False

        # Parse login response
        try:
            root = ET.fromstring(resp.text)
            ns = {'ns': 'http://www.isapi.org/ver20/XMLSchema'}

            status_value = root.find('.//ns:statusValue', ns)
            status_string = root.find('.//ns:statusString', ns)
            session_tag = root.find('.//ns:sessionTag', ns)

            # Check if login was successful
            if status_value is not None and status_value.text == "200":
                print("[+] Login successful!")
                self.session_id = session_id

                # NEW: Extract and store sessionTag
                if session_tag is not None:
                    self.session_tag = session_tag.text
                    print(f"    Session Tag: {self.session_tag[:32]}...")
                else:
                    print("    [!] Warning: No sessionTag in response")

                return True
            else:
                print("[!] Login failed!")
                print(f"[!] Response: {resp.text}")
                return False

        except Exception as e:
            print(f"[!] Error parsing login response: {e}")
            print(f"[!] Response: {resp.text}")
            return False

    def _encrypt_password(self, password, username, challenge, salt, iterations, is_irreversible):
        """Encrypt password according to Hikvision algorithm"""
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

    def _derive_aes_key(self, password, username, salt, iterations, is_irreversible):
        """Derive AES key for data decryption"""
        if is_irreversible:
            # irreversible_key = SHA256(username + salt + password)
            irreversible_key = hashlib.sha256((username + salt + password).encode()).hexdigest()
        else:
            irreversible_key = hashlib.sha256(password.encode()).hexdigest()

        # aes_key = SHA256(irreversible_key + "AaBbCcDd1234!@#$")
        aes_key = hashlib.sha256((irreversible_key + "AaBbCcDd1234!@#$").encode()).hexdigest()

        # Iterate
        for i in range(1, iterations):
            aes_key = hashlib.sha256(aes_key.encode()).hexdigest()

        # Take first 32 characters for 128-bit AES key
        return aes_key[:32]

    def _add_session_headers(self, headers=None):
        """
        Add session cookie and sessionTag to request headers

        Args:
            headers: Existing headers dict or None

        Returns:
            Headers dict with session info added
        """
        if headers is None:
            headers = {}

        # NEW: Add sessionTag header if available
        if self.session_tag:
            headers['sessiontag'] = self.session_tag

        return headers

    def heartbeat(self):
        """Send heartbeat to keep session alive"""
        url = f"{self.protocol}://{self.ip}/ISAPI/Security/sessionHeartbeat"
        try:
            # NEW: Add sessionTag header
            headers = self._add_session_headers()
            resp = self.session.put(url, headers=headers, timeout=10)
            return resp.status_code == 200
        except:
            return False

    def decrypt_field(self, encrypted_hex, iv_hex):
        """
        Decrypt AES-128-CBC encrypted field

        Args:
            encrypted_hex: Encrypted data as hex string
            iv_hex: Initialization vector as hex string

        Returns:
            Decrypted string
        """
        # Convert hex to bytes
        key_bytes = bytes.fromhex(self.aes_key)
        iv_bytes = bytes.fromhex(iv_hex)
        cipher_bytes = bytes.fromhex(encrypted_hex)

        # Create cipher
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

        # Decrypt
        decrypted = cipher.decrypt(cipher_bytes)

        # Try different decoding methods

        # Method 1: Direct UTF-8 decode (no padding, no base64)
        try:
            result = decrypted.decode('utf-8').rstrip('\x00')
            if result.isprintable() or all(c.isprintable() or c in '\n\r\t' for c in result):
                return result
        except:
            pass

        # Method 2: Remove null bytes and decode
        try:
            result = decrypted.rstrip(b'\x00').decode('utf-8')
            if result.isprintable() or all(c.isprintable() or c in '\n\r\t' for c in result):
                return result
        except:
            pass

        # Method 3: Try unpadding with PKCS7
        try:
            unpadded = unpad(decrypted, AES.block_size)
            result = unpadded.decode('utf-8')
            return result
        except:
            pass

        # Method 4: Try base64 decode after unpadding
        try:
            unpadded = unpad(decrypted, AES.block_size)
            result = b64decode(unpadded).decode('utf-8')
            return result
        except:
            pass

        # Method 5: Try base64 decode without unpadding
        try:
            result = b64decode(decrypted).decode('utf-8')
            return result
        except:
            pass

        # If all methods fail, return the encrypted value
        print(f"[!] All decryption methods failed for: {encrypted_hex[:32]}...")
        print(f"[!] Decrypted raw (hex): {decrypted.hex()}")
        print(f"[!] Decrypted raw (repr): {repr(decrypted)}")
        return encrypted_hex

    def get_device_info(self):
        """Get basic device information"""
        url = f"{self.protocol}://{self.ip}/ISAPI/System/deviceInfo"
        try:
            # NEW: Add sessionTag header
            headers = self._add_session_headers()
            resp = self.session.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.text
            else:
                return None
        except Exception as e:
            print(f"[!] Error getting device info: {e}")
            return None

    def get_security_capabilities(self):
        """Get security capabilities"""
        url = f"{self.protocol}://{self.ip}/ISAPI/Security/capabilities?username={self.username}"
        try:
            # NEW: Add sessionTag header
            headers = self._add_session_headers()
            resp = self.session.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.text
            else:
                return None
        except Exception as e:
            print(f"[!] Error getting security capabilities: {e}")
            return None

    def get_streaming_channels(self):
        """Get streaming channel information"""
        url = f"{self.protocol}://{self.ip}/ISAPI/Streaming/channels"
        try:
            # NEW: Add sessionTag header
            headers = self._add_session_headers()
            resp = self.session.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.text
            else:
                return None
        except Exception as e:
            print(f"[!] Error getting channels: {e}")
            return None

    def fetch_events(self, major_filter=0, minor_filter=0, start_time=None, end_time=None, max_results=30, try_decrypt=False):
        """
        Fetch access control events (attendance records)

        Args:
            major_filter: Major event type (0=all, 1=door events, etc.)
            minor_filter: Minor event type (0=all)
            start_time: Start time in format "2024-01-01T00:00:00" (timezone offset will be added)
            end_time: End time in format "2024-01-01T23:59:59" (timezone offset will be added)
            max_results: Maximum number of results to return
            try_decrypt: Whether to request encrypted response and attempt decryption

        Returns:
            Dictionary containing event data
        """
        import uuid
        from datetime import datetime, timedelta

        # Set default time range if not provided (today's date)
        if not start_time:
            start_dt = datetime.now().replace(hour=0, minute=0, second=0)
            start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%S")
        if not end_time:
            end_dt = datetime.now().replace(hour=23, minute=59, second=59)
            end_time = end_dt.strftime("%Y-%m-%dT%H:%M:%S")

        # Add timezone offset to times (format: "2026-01-07T00:00:00+03:00")
        # Using +03:00 timezone offset
        start_time_with_tz = f"{start_time}+03:00"
        end_time_with_tz = f"{end_time}+03:00"

        search_id = str(uuid.uuid4())

        if try_decrypt and self.aes_key:
            # Generate random IV (16 bytes = 32 hex chars)
            iv = secrets.token_hex(16)
            print(f"[*] Fetching events with encryption (IV: {iv})...")
            url = f"{self.protocol}://{self.ip}/ISAPI/AccessControl/AcsEvent?format=json&security=1&iv={iv}"
        else:
            print(f"[*] Fetching events without encryption...")
            url = f"{self.protocol}://{self.ip}/ISAPI/AccessControl/AcsEvent?format=json"
            iv = None

        payload = {
            "AcsEventCond": {
                "searchID": search_id,
                "searchResultPosition": 0,
                "maxResults": max_results,
                "major": major_filter,
                "minor": minor_filter,
                "startTime": start_time_with_tz,
                "endTime": end_time_with_tz
            }
        }

        try:
            # NEW: Add sessionTag header
            headers = self._add_session_headers({'Content-Type': 'application/json'})
            resp = self.session.post(url, json=payload, headers=headers, timeout=10)
            resp.raise_for_status()
        except Exception as e:
            print(f"[!] Error fetching events: {e}")
            if 'resp' in locals():
                print(f"[!] Response: {resp.text}")
            return None

        # Parse response
        try:
            data = resp.json()
        except:
            print(f"[!] Failed to parse JSON response")
            print(f"[!] Response: {resp.text}")
            return None

        # Process events
        acs_event = data.get('AcsEvent', {})

        # Check if it's an InfoList structure
        if 'InfoList' in acs_event:
            events = acs_event['InfoList']
            total = acs_event.get('totalMatches', len(events))
        else:
            events = [acs_event] if acs_event else []
            total = len(events)

        print(f"[*] Found {len(events)} events (total: {total})")

        # Decrypt encrypted fields if requested
        if try_decrypt and iv:
            for event in events:
                # Decrypt name if present
                if 'name' in event and event['name']:
                    decrypted = self.decrypt_field(event['name'], iv)
                    print(f"    Name (encrypted): {event['name'][:32]}...")
                    print(f"    Name (decrypted): {decrypted}")
                    event['name_decrypted'] = decrypted

                if 'employeeNoString' in event and event['employeeNoString']:
                    decrypted = self.decrypt_field(event['employeeNoString'], iv)
                    print(f"    Employee (encrypted): {event['employeeNoString'][:32]}...")
                    print(f"    Employee (decrypted): {decrypted}")
                    event['employeeNoString_decrypted'] = decrypted
        else:
            # Display plaintext values
            for i, event in enumerate(events[:5], 1):  # Show first 5
                print(f"\n  Event {i}:")
                if 'time' in event:
                    print(f"    Time: {event['time']}")
                if 'employeeNoString' in event:
                    print(f"    Employee: {event['employeeNoString']}")
                if 'name' in event:
                    print(f"    Name: {event['name']}")
                if 'cardNo' in event:
                    print(f"    Card: {event['cardNo']}")
                if 'doorNo' in event:
                    print(f"    Door: {event['doorNo']}")
            if len(events) > 5:
                print(f"\n  ... and {len(events) - 5} more events")

        return data

    def fetch_users(self, max_results=20, start_position=0, try_decrypt=True):
        """
        Fetch user list with encrypted response

        Args:
            max_results: Maximum number of results to return
            start_position: Starting position for pagination
            try_decrypt: Whether to request encrypted response and attempt decryption

        Returns:
            Dictionary containing user data
        """
        search_id = str(uuid.uuid4())
        payload = {
            "UserInfoSearchCond": {
                "searchID": search_id,
                "maxResults": max_results,
                "searchResultPosition": start_position
            }
        }

        if try_decrypt and self.aes_key:
            # Generate random IV (16 bytes = 32 hex chars)
            iv = secrets.token_hex(16)
            print(f"[*] Fetching users with encryption (IV: {iv})...")
            url = f"{self.protocol}://{self.ip}/ISAPI/AccessControl/UserInfo/Search?format=json&security=1&iv={iv}"
        else:
            print(f"[*] Fetching users without encryption...")
            url = f"{self.protocol}://{self.ip}/ISAPI/AccessControl/UserInfo/Search?format=json"
            iv = None

        try:
            # NEW: Add sessionTag header
            headers = self._add_session_headers({'Content-Type': 'application/json'})
            resp = self.session.post(url, json=payload, headers=headers, timeout=10)
            resp.raise_for_status()
        except Exception as e:
            print(f"[!] Error fetching users: {e}")
            return None

        # Parse response
        try:
            data = resp.json()
        except:
            print(f"[!] Failed to parse JSON response")
            print(f"[!] Response: {resp.text}")
            return None

        # Decrypt encrypted fields if requested
        user_info_search = data.get('UserInfoSearch', {})
        users = user_info_search.get('UserInfo', [])

        print(f"[*] Found {len(users)} users")

        if try_decrypt and iv:
            for user in users:
                # Decrypt employeeNo and name
                if 'employeeNo' in user and user['employeeNo']:
                    decrypted = self.decrypt_field(user['employeeNo'], iv)
                    print(f"    Employee No (encrypted): {user['employeeNo'][:32]}...")
                    print(f"    Employee No (decrypted): {decrypted}")
                    user['employeeNo_decrypted'] = decrypted

                if 'name' in user and user['name']:
                    decrypted = self.decrypt_field(user['name'], iv)
                    print(f"    Name (encrypted): {user['name'][:32]}...")
                    print(f"    Name (decrypted): {decrypted}")
                    user['name_decrypted'] = decrypted
        else:
            # Display plaintext values
            for user in users:
                if 'employeeNo' in user:
                    print(f"    Employee No: {user['employeeNo']}")
                if 'name' in user:
                    print(f"    Name: {user['name']}")

        return data


def main():
    """Example usage"""
    import argparse

    parser = argparse.ArgumentParser(description='Hikvision Device Client V2 with SessionTag Support')
    parser.add_argument('ip', help='Device IP address')
    parser.add_argument('-u', '--username', default='admin', help='Username (default: admin)')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('--https', action='store_true', help='Use HTTPS')
    parser.add_argument('--users', action='store_true', help='Fetch user list')
    parser.add_argument('--events', action='store_true', help='Fetch access control events (attendance)')
    parser.add_argument('--no-decrypt', action='store_true', help='Fetch users without encryption')
    parser.add_argument('--info', action='store_true', help='Get device info')
    parser.add_argument('--security-caps', action='store_true', help='Get security capabilities')
    parser.add_argument('--channels', action='store_true', help='Get streaming channels')
    parser.add_argument('--start-time', help='Event start time (format: 2024-01-01T00:00:00)')
    parser.add_argument('--end-time', help='Event end time (format: 2024-01-01T23:59:59)')
    parser.add_argument('--max-results', type=int, default=30, help='Maximum results (default: 30)')

    args = parser.parse_args()

    # Create client
    client = HikvisionClientV2(args.ip, args.username, args.password, use_https=args.https)

    # Login
    if not client.login():
        print("[!] Login failed. Exiting.")
        return

    print()

    # Get device info
    if args.info:
        print("[*] Getting device info...")
        info = client.get_device_info()
        if info:
            print(info)
        print()

    # Get security capabilities
    if args.security_caps:
        print("[*] Getting security capabilities...")
        caps = client.get_security_capabilities()
        if caps:
            print(caps)
        print()

    # Get streaming channels
    if args.channels:
        print("[*] Getting streaming channels...")
        channels = client.get_streaming_channels()
        if channels:
            print(channels)
        print()

    # Fetch users
    if args.users:
        if args.no_decrypt:
            print("[*] Fetching users without encryption...")
            users = client.fetch_users(max_results=args.max_results, try_decrypt=False)
        else:
            print("[*] Fetching users (defaulting to plaintext - encryption not yet working)...")
            users = client.fetch_users(max_results=args.max_results, try_decrypt=False)
        if users:
            import json
            print(json.dumps(users, indent=2))

    # Fetch events
    if args.events:
        print("[*] Fetching access control events...")
        events = client.fetch_events(
            start_time=args.start_time,
            end_time=args.end_time,
            max_results=args.max_results,
            try_decrypt=False  # Defaulting to plaintext since encryption doesn't work yet
        )
        if events:
            import json
            print("\n" + json.dumps(events, indent=2))


if __name__ == '__main__':
    main()
