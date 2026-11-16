"""
Zenith Auth - Official Python SDK with Binary Integrity & Anti-Tamper Engine
Supports Windows/Linux/macOS with Hardware Lock, Executable SHA-256 Hash Verification,
and Anti-Debug / Anti-Reversing Protection.
"""

import os
import sys
import requests
import json
import uuid
import platform
import hashlib
import subprocess

class ZenithAuth:
    def __init__(self, app_id: int, public_key: str, base_url: str = "http://127.0.0.1:3000/api/v1/client"):
        self.app_id = app_id
        self.public_key = public_key
        self.base_url = base_url.rstrip('/')
        self.session_token = None
        self.user_data = None

        # Pre-screen environment and calculate SHA-256 hash
        self.check_security_integrity()
        self.cached_hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """
        Calculates SHA-256 hash of the running executable or main script.
        If the file is modified, unpacked, or patched, the hash changes and server rejects access.
        """
        try:
            if getattr(sys, 'frozen', False):
                target_path = sys.executable
            else:
                target_path = os.path.abspath(sys.argv[0])

            if not os.path.exists(target_path):
                return ""

            sha256 = hashlib.sha256()
            with open(target_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest().lower()
        except Exception:
            return ""

    def check_security_integrity(self) -> bool:
        """
        Active Anti-Debug and Anti-Cracking Protection Suite.
        Immediately halts execution if debugger or reversing tools are active.
        """
        # 1. Python trace detection (pdb / PyCharm / VS Code debugger)
        if sys.gettrace() is not None:
            os._exit(0xDEAD)

        # 2. Windows-specific process scanning for known reversing tools
        if platform.system() == "Windows":
            blacklisted = [
                "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
                "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe",
                "dnspy.exe", "httpdebuggerui.exe", "httpdebugger.exe",
                "fiddler.exe", "charles.exe", "wireshark.exe", "processhacker.exe",
                "scylla.exe", "pestudio.exe", "ghidra.exe", "ollydbg.exe"
            ]
            try:
                # Quick non-blocking process check
                output = subprocess.check_output("tasklist /NH /FO CSV", shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore').lower()
                for tool in blacklisted:
                    if tool in output:
                        os._exit(0xDEAD)
            except Exception:
                pass

        return True

    def get_hwid(self) -> str:
        """Generates a hardware identifier based on machine nodes and processor info"""
        raw = f"{platform.node()}-{uuid.getnode()}-{platform.processor()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24].upper()

    def initialize(self, client_version: str = "2.5.0") -> bool:
        """Performs initial integrity handshake with Zenith Auth servers"""
        self.check_security_integrity()
        payload = {
            "app_id": self.app_id,
            "public_key": self.public_key,
            "client_version": client_version,
            "hash": self.cached_hash
        }
        try:
            resp = requests.post(f"{self.base_url}/init", json=payload, timeout=8)
            data = resp.json()
            return resp.status_code == 200 and data.get("status") is True
        except Exception as e:
            print(f"[Zenith Security] Handshake Error: {e}")
            return False

    def login(self, username: str, password: str, hwid: str = None) -> dict:
        """Authenticates user credentials and verifies binary hash + HWID"""
        self.check_security_integrity()
        if not hwid:
            hwid = self.get_hwid()
        payload = {
            "username": username,
            "password": password,
            "hwid": hwid,
            "app_id": self.app_id,
            "hash": self.cached_hash
        }
        resp = requests.post(f"{self.base_url}/login", json=payload, timeout=8)
        data = resp.json()
        if data.get("status"):
            self.session_token = data.get("token")
            self.user_data = data.get("user")
        return data

    def register(self, username: str, email: str, password: str, license_key: str, hwid: str = None) -> dict:
        """Registers a new account using an unredeemed license key with hash check"""
        self.check_security_integrity()
        if not hwid:
            hwid = self.get_hwid()
        payload = {
            "username": username,
            "email": email,
            "password": password,
            "license_key": license_key,
            "hwid": hwid,
            "app_id": self.app_id,
            "hash": self.cached_hash
        }
        resp = requests.post(f"{self.base_url}/register", json=payload, timeout=8)
        return resp.json()

    def verify_license(self, license_key: str, hwid: str = None) -> dict:
        """Checks license validity, duration, and expiration status with binary hash"""
        self.check_security_integrity()
        if not hwid:
            hwid = self.get_hwid()
        payload = {
            "license_key": license_key,
            "hwid": hwid,
            "app_id": self.app_id,
            "hash": self.cached_hash
        }
        resp = requests.post(f"{self.base_url}/license/verify", json=payload, timeout=8)
        return resp.json()

    def get_variables(self, username: str = None) -> dict:
        """Retrieves global and user-specific variables"""
        self.check_security_integrity()
        payload = {
            "app_id": self.app_id,
            "username": username or (self.user_data.get("username") if self.user_data else None),
            "hash": self.cached_hash
        }
        resp = requests.post(f"{self.base_url}/vars", json=payload, timeout=8)
        return resp.json()

    def ping(self) -> bool:
        """Sends session keepalive heartbeat"""
        self.check_security_integrity()
        if not self.session_token:
            return False
        resp = requests.post(f"{self.base_url}/session/ping", json={"session_token": self.session_token}, timeout=5)
        return resp.status_code == 200
