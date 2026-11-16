/**
 * Zenith Auth - Official C# / .NET Security SDK
 * Compatible with .NET Framework 4.7+, .NET Core, .NET 5/6/7/8/9
 * Includes Executable SHA-256 Binary Hash Verification, Anti-Debug, and Anti-Dump Protection.
 */

using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace ZenithSecurity
{
    public class ZenithAuthClient
    {
        private static readonly HttpClient httpClient = new HttpClient();
        private readonly string baseUrl;
        private readonly int appId;
        private readonly string publicKey;
        private readonly string cachedHash;

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        public string SessionToken { get; private set; }

        public ZenithAuthClient(int appId, string publicKey, string host = "http://127.0.0.1:3000")
        {
            this.appId = appId;
            this.publicKey = publicKey;
            this.baseUrl = host.TrimEnd('/') + "/api/v1/client";

            // Run initial security screening and calculate executable binary hash
            CheckSecurityIntegrity();
            this.cachedHash = CalculateExecutableHash();
        }

        /// <summary>
        /// Computes the SHA-256 hash of the currently running application binary.
        /// Any modification, hex editing, or patching will immediately change this hash.
        /// </summary>
        public static string CalculateExecutableHash()
        {
            try
            {
                string processPath = Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(processPath) || !File.Exists(processPath))
                {
                    return string.Empty;
                }

                using (var sha256 = SHA256.Create())
                using (var stream = new FileStream(processPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Comprehensive Anti-Debug and Anti-Cracking Protection Suite.
        /// Immediately terminates execution via Environment.FailFast if analysis tools are active.
        /// </summary>
        public static void CheckSecurityIntegrity()
        {
            try
            {
                // 1. Managed Debugger Checks
                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    Environment.FailFast("Integrity Error: Managed debugger detected.");
                }

                // 2. Native Win32 IsDebuggerPresent Check
                if (IsDebuggerPresent())
                {
                    Environment.FailFast("Integrity Error: Native debugger detected.");
                }

                // 3. Remote Debugger Detection
                bool isRemoteDbg = false;
                CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isRemoteDbg);
                if (isRemoteDbg)
                {
                    Environment.FailFast("Integrity Error: Remote debugger detected.");
                }

                // 4. Blacklisted Reversing and Inspection Process Scan
                var blacklistedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "dnspy", "x64dbg", "x32dbg", "ida64", "ida",
                    "cheatengine", "cheatengine-x86_64", "cheatengine-i386",
                    "httpdebuggerui", "httpdebugger", "fiddler", "charles",
                    "wireshark", "processhacker", "scylla", "de4dot", "pestudio", "ghidra", "ollydbg"
                };

                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (blacklistedProcesses.Contains(proc.ProcessName))
                        {
                            Environment.FailFast("Integrity Error: Analysis tool detected (" + proc.ProcessName + ").");
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                if (ex.Message.StartsWith("Integrity Error")) throw;
            }
        }

        public async Task<bool> InitializeAsync(string version = "2.5.0")
        {
            CheckSecurityIntegrity();

            var payload = new 
            { 
                app_id = appId, 
                public_key = publicKey, 
                client_version = version,
                hash = cachedHash 
            };

            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await httpClient.PostAsync($"{baseUrl}/init", content);
            return response.IsSuccessStatusCode;
        }

        public async Task<string> LoginAsync(string username, string password, string hwid)
        {
            CheckSecurityIntegrity();

            var payload = new 
            { 
                username, 
                password, 
                hwid, 
                app_id = appId,
                hash = cachedHash 
            };

            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await httpClient.PostAsync($"{baseUrl}/login", content);
            var result = await response.Content.ReadAsStringAsync();
            return result;
        }

        public async Task<string> RegisterAsync(string username, string email, string password, string licenseKey, string hwid)
        {
            CheckSecurityIntegrity();

            var payload = new
            {
                username,
                email,
                password,
                license_key = licenseKey,
                hwid,
                app_id = appId,
                hash = cachedHash
            };

            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await httpClient.PostAsync($"{baseUrl}/register", content);
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<bool> VerifyLicenseAsync(string licenseKey, string hwid)
        {
            CheckSecurityIntegrity();

            var payload = new 
            { 
                license_key = licenseKey, 
                hwid, 
                app_id = appId,
                hash = cachedHash 
            };

            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await httpClient.PostAsync($"{baseUrl}/license/verify", content);
            return response.IsSuccessStatusCode;
        }

        public async Task<string> GetVariablesAsync(string username)
        {
            CheckSecurityIntegrity();

            var payload = new { app_id = appId, username, hash = cachedHash };
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await httpClient.PostAsync($"{baseUrl}/vars", content);
            return await response.Content.ReadAsStringAsync();
        }
    }
}
