/**
 * Zenith Auth - Official JavaScript SDK (Browser & Node.js)
 * Includes SHA-256 binary/script integrity check for Node.js environments.
 */

class ZenithAuth {
  constructor(appId, publicKey, host = 'http://127.0.0.1:3000') {
    this.appId = appId;
    this.publicKey = publicKey;
    this.baseUrl = `${host.replace(/\/$/, '')}/api/v1/client`;
    this.sessionToken = null;
    this.cachedHash = this.calculateHash();
  }

  calculateHash() {
    if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = require('crypto');
        const fs = require('fs');
        const targetPath = process.argv[1] || process.execPath;
        if (targetPath && fs.existsSync(targetPath)) {
          const fileBuffer = fs.readFileSync(targetPath);
          return crypto.createHash('sha256').update(fileBuffer).digest('hex');
        }
      } catch (e) {}
    }
    return '';
  }

  async init(clientVersion = '2.5.0') {
    const res = await fetch(`${this.baseUrl}/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        app_id: this.appId, 
        public_key: this.publicKey, 
        client_version: clientVersion,
        hash: this.cachedHash 
      })
    });
    const data = await res.json();
    return data.status === true;
  }

  async login(username, password, hwid = 'BROWSER-SESSION') {
    const res = await fetch(`${this.baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        username, 
        password, 
        hwid, 
        app_id: this.appId,
        hash: this.cachedHash 
      })
    });
    const data = await res.json();
    if (data.status) {
      this.sessionToken = data.token;
    }
    return data;
  }

  async register(username, email, password, licenseKey, hwid = 'BROWSER-SESSION') {
    const res = await fetch(`${this.baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        username, 
        email, 
        password, 
        license_key: licenseKey, 
        hwid, 
        app_id: this.appId,
        hash: this.cachedHash 
      })
    });
    return await res.json();
  }

  async verifyLicense(licenseKey, hwid = 'BROWSER-SESSION') {
    const res = await fetch(`${this.baseUrl}/license/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        license_key: licenseKey, 
        hwid, 
        app_id: this.appId,
        hash: this.cachedHash 
      })
    });
    return await res.json();
  }

  async getVariables(username) {
    const res = await fetch(`${this.baseUrl}/vars`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        app_id: this.appId, 
        username,
        hash: this.cachedHash 
      })
    });
    return await res.json();
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ZenithAuth;
}
