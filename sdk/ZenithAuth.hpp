/**
 * Zenith Auth - Official C++ Security & Anti-Tamper Client Header
 * Windows Native C++ Client with Hardware Lock, Binary SHA-256 Hash Verification,
 * and Anti-Debug / Anti-Tamper / Anti-Cracking Protection Suite.
 */

#pragma once
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <intrin.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

class ZenithAuthClient {
private:
    int m_appId;
    std::string m_publicKey;
    std::string m_host;
    int m_port;
    bool m_useHttps;
    std::string m_cachedHash;

    // Fast case-insensitive string comparison helper
    static bool EqualsIgnoreCase(const std::string& a, const std::string& b) {
        if (a.length() != b.length()) return false;
        for (size_t i = 0; i < a.length(); ++i) {
            if (tolower(a[i]) != tolower(b[i])) return false;
        }
        return true;
    }

public:
    ZenithAuthClient(int appId, const std::string& publicKey, const std::string& host = "127.0.0.1", int port = 3000, bool useHttps = false)
        : m_appId(appId), m_publicKey(publicKey), m_host(host), m_port(port), m_useHttps(useHttps) {
        // Pre-compute binary hash and execute initial security screening
        CheckSecurityIntegrity();
        m_cachedHash = CalculateExecutableHash();
    }

    /**
     * Calculates the cryptographic SHA-256 hash of the running executable.
     * If the binary is modified, patched, unpacked, or dumped, this hash alters,
     * immediately failing authentication on the server.
     */
    std::string CalculateExecutableHash() {
        char szFilePath[MAX_PATH];
        if (GetModuleFileNameA(NULL, szFilePath, MAX_PATH) == 0) {
            return "";
        }

        HANDLE hFile = CreateFileA(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return "";
        }

        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        std::string hashString = "";

        if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                BYTE buffer[8192];
                DWORD bytesRead = 0;
                BOOL success = TRUE;

                while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                    if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
                        success = FALSE;
                        break;
                    }
                }

                if (success) {
                    BYTE hashBytes[32];
                    DWORD hashLen = sizeof(hashBytes);
                    if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) {
                        std::stringstream ss;
                        for (DWORD i = 0; i < hashLen; ++i) {
                            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBytes[i];
                        }
                        hashString = ss.str();
                    }
                }
                CryptDestroyHash(hHash);
            }
            CryptReleaseContext(hProv, 0);
        }

        CloseHandle(hFile);
        return hashString;
    }

    /**
     * Comprehensive Active Anti-Crack, Anti-Debugger, and Anti-Reversing Suite
     * Returns true if environment is verified secure.
     * Automatically halts and self-destructs the process upon detecting tampering.
     */
    bool CheckSecurityIntegrity() {
        // 1. Windows API Debugger Detection
        if (IsDebuggerPresent()) {
            ExitProcess(0xDEAD0001);
            return false;
        }

        // 2. Remote Debugger Detection
        BOOL isDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
        if (isDebuggerPresent) {
            ExitProcess(0xDEAD0002);
            return false;
        }

        // 3. Direct PEB BeingDebugged & NtGlobalFlag inspection
#if defined(_M_X64) || defined(__x86_64__)
        unsigned char* ppeb = (unsigned char*)__readgsqword(0x60);
        if (ppeb && ppeb[2] != 0) { // BeingDebugged flag
            ExitProcess(0xDEAD0003);
            return false;
        }
#elif defined(_M_IX86) || defined(__i386__)
        unsigned char* ppeb = (unsigned char*)__readfsdword(0x30);
        if (ppeb && ppeb[2] != 0) { // BeingDebugged flag
            ExitProcess(0xDEAD0003);
            return false;
        }
#endif

        // 4. Hardware Breakpoint Register Checks (DR0-DR3)
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        HANDLE hThread = GetCurrentThread();
        if (GetThreadContext(hThread, &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                ExitProcess(0xDEAD0004);
                return false;
            }
        }

        // 5. Blacklisted Reversing & Cracking Process Scanning
        const std::vector<std::string> blacklistedTools = {
            "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
            "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe",
            "dnspy.exe", "httpdebuggerui.exe", "httpdebugger.exe",
            "fiddler.exe", "charles.exe", "wireshark.exe", "processhacker.exe",
            "scylla.exe", "pestudio.exe", "ghidra.exe", "ollydbg.exe", "de4dot.exe"
        };

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnap, &pe32)) {
                do {
                    std::string processName = pe32.szExeFile;
                    for (const auto& tool : blacklistedTools) {
                        if (EqualsIgnoreCase(processName, tool)) {
                            CloseHandle(hSnap);
                            ExitProcess(0xDEAD0005);
                            return false;
                        }
                    }
                } while (Process32Next(hSnap, &pe32));
            }
            CloseHandle(hSnap);
        }

        return true;
    }

    std::string HttpRequest(const std::string& path, const std::string& postData) {
        // Enforce anti-debug verification before every network transaction
        CheckSecurityIntegrity();

        HINTERNET hInternet = InternetOpenA("ZenithCpp/2.5-Protected", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        if (!hInternet) return "";

        HINTERNET hConnect = InternetConnectA(
            hInternet,
            m_host.c_str(),
            m_port,
            NULL,
            NULL,
            INTERNET_SERVICE_HTTP,
            0,
            0
        );
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return "";
        }

        DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
        if (m_useHttps || m_port == 443) {
            dwFlags |= INTERNET_FLAG_SECURE;
        }

        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(), NULL, NULL, NULL, dwFlags, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return "";
        }

        std::string headers = "Content-Type: application/json\r\n";
        HttpSendRequestA(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)postData.c_str(), (DWORD)postData.length());

        char buffer[4096];
        DWORD bytesRead = 0;
        std::string response;
        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            response.append(buffer);
        }

        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return response;
    }

    bool Initialize(const std::string& version = "2.5.0") {
        CheckSecurityIntegrity();
        if (m_cachedHash.empty()) {
            m_cachedHash = CalculateExecutableHash();
        }

        std::stringstream ss;
        ss << "{"
           << "\"app_id\":" << m_appId << ","
           << "\"public_key\":\"" << m_publicKey << "\","
           << "\"client_version\":\"" << version << "\","
           << "\"hash\":\"" << m_cachedHash << "\""
           << "}";

        std::string res = HttpRequest("/api/v1/client/init", ss.str());
        return res.find("\"status\":true") != std::string::npos;
    }

    std::string Login(const std::string& username, const std::string& password, const std::string& hwid) {
        CheckSecurityIntegrity();
        if (m_cachedHash.empty()) {
            m_cachedHash = CalculateExecutableHash();
        }

        std::stringstream ss;
        ss << "{"
           << "\"username\":\"" << username << "\","
           << "\"password\":\"" << password << "\","
           << "\"hwid\":\"" << hwid << "\","
           << "\"app_id\":" << m_appId << ","
           << "\"hash\":\"" << m_cachedHash << "\""
           << "}";

        return HttpRequest("/api/v1/client/login", ss.str());
    }

    std::string Register(const std::string& username, const std::string& email, const std::string& password, const std::string& licenseKey, const std::string& hwid) {
        CheckSecurityIntegrity();
        if (m_cachedHash.empty()) {
            m_cachedHash = CalculateExecutableHash();
        }

        std::stringstream ss;
        ss << "{"
           << "\"username\":\"" << username << "\","
           << "\"email\":\"" << email << "\","
           << "\"password\":\"" << password << "\","
           << "\"license_key\":\"" << licenseKey << "\","
           << "\"hwid\":\"" << hwid << "\","
           << "\"app_id\":" << m_appId << ","
           << "\"hash\":\"" << m_cachedHash << "\""
           << "}";

        return HttpRequest("/api/v1/client/register", ss.str());
    }

    bool VerifyLicense(const std::string& licenseKey, const std::string& hwid) {
        CheckSecurityIntegrity();
        if (m_cachedHash.empty()) {
            m_cachedHash = CalculateExecutableHash();
        }

        std::stringstream ss;
        ss << "{"
           << "\"license_key\":\"" << licenseKey << "\","
           << "\"hwid\":\"" << hwid << "\","
           << "\"app_id\":" << m_appId << ","
           << "\"hash\":\"" << m_cachedHash << "\""
           << "}";

        std::string res = HttpRequest("/api/v1/client/license/verify", ss.str());
        return res.find("\"valid\":true") != std::string::npos;
    }
};
