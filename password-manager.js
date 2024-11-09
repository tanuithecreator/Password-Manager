"use strict";

/********* External Imports ********/
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/
const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // maximum password length

class Keychain {
  constructor() {
    this.data = {};  // Store public information here (non-sensitive)
    this.secrets = {}; // Store private information here (sensitive keys)
  };

  /**
   * Initializes an empty keychain with the provided password.
   * Derives keys for HMAC (for domains) and AES-GCM (for passwords).
   */
  static async init(password) {
    let keychain = new Keychain();
    
    // Derive the base key from the password
    const passwordBuffer = stringToBuffer(password);
    const baseKey = await subtle.importKey("raw", passwordBuffer, "PBKDF2", false, ["deriveKey"]);
    const salt = getRandomBytes(16);  // Random salt

    // PBKDF2 to derive the master key from the password and salt
    const masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      baseKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"]
    );

    // Create HMAC and AES-GCM keys from master key
    keychain.secrets.hmacKey = masterKey;
    keychain.secrets.aesKey = await subtle.importKey(
      "raw",
      getRandomBytes(32), // Random bytes for AES-GCM key
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );

    // Store salt in public data for key derivation during load
    keychain.data.salt = encodeBuffer(salt);

    return keychain;
  }

  /**
   * Loads a keychain from the provided serialized representation and password.
   * Verifies the integrity using SHA-256 if `trustedDataCheck` is provided.
   */
  static async load(password, repr, trustedDataCheck) {
    const parsedData = JSON.parse(repr);
    const salt = decodeBuffer(parsedData.salt);

    // Re-derive master key for HMAC and AES-GCM using PBKDF2
    const passwordBuffer = stringToBuffer(password);
    const baseKey = await subtle.importKey("raw", passwordBuffer, "PBKDF2", false, ["deriveKey"]);
    const masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      baseKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"]
    );

    // Validate integrity if trustedDataCheck is provided
    if (trustedDataCheck) {
      const computedHash = await subtle.digest("SHA-256", stringToBuffer(repr));
      if (bufferToString(computedHash) !== trustedDataCheck) {
        throw new Error("Integrity check failed.");
      }
    }

    let keychain = new Keychain();
    keychain.data = parsedData;
    keychain.secrets.hmacKey = masterKey;
    keychain.secrets.aesKey = await subtle.importKey(
      "raw",
      getRandomBytes(32),
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );

    return keychain;
  }

  /**
   * Serializes the keychain contents and computes a SHA-256 hash for integrity.
   */
  async dump() {
    const jsonData = JSON.stringify(this.data);
    const hashBuffer = await subtle.digest("SHA-256", stringToBuffer(jsonData));
    return [jsonData, bufferToString(hashBuffer)];
  }

  /**
   * Encrypts and stores the password associated with the domain in the KVS.
   */
  async set(name, value) {
    const iv = getRandomBytes(12); // Generate a unique IV for AES-GCM
    const nameHmac = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    const nameKey = encodeBuffer(nameHmac);

    const encryptedValue = await subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      this.secrets.aesKey,
      stringToBuffer(value)
    );

    this.data[nameKey] = {
      value: encodeBuffer(encryptedValue),
      iv: encodeBuffer(iv)
    };
  }

  /**
   * Retrieves and decrypts the password for the specified domain.
   */
  async get(name) {
    const nameHmac = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    const nameKey = encodeBuffer(nameHmac);
    
    if (!this.data[nameKey]) return null;

    const { value, iv } = this.data[nameKey];
    const decryptedValue = await subtle.decrypt(
      { name: "AES-GCM", iv: decodeBuffer(iv) },
      this.secrets.aesKey,
      decodeBuffer(value)
    );

    return bufferToString(decryptedValue);
  }

  /**
   * Removes a record from the password manager for the given domain name.
   */
  async remove(name) {
    const nameHmac = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    const nameKey = encodeBuffer(nameHmac);

    if (this.data[nameKey]) {
      delete this.data[nameKey];
      return true;
    }
    return false;
  }
}

module.exports = { Keychain };
