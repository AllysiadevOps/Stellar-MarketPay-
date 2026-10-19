"sust";

const crypto = require("crypto");

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const KEY_ENV_VAR = "DATABASE_ENCRYPTION_KEY";
const MIN_KEY_LENGTH = 16;

function getEncryptionKey() {
  const key = process.env && process.env[KEY_ENV_VAR];
  if (!key || key.length < MIN_KEY_LENGTH) {
    throw new Error(`${KEY_ENV_VAR} must be at least ${MIN_KEY_LENGTH} characters`);
  }

  // Ensure the key is exactly 32 bytes for aes-256-gcm.
  // If the user provided key is exactly 32 bytes, use it directly.
  // Otherwise, hash it to 32 bytes.
  const keyBuffer = Buffer.from(key, "utf8");
  if (keyBuffer.length === 32) {
    return keyBuffer;
  }
  return crypto.createHash("sha256").update(keyBuffer).digest();
}

function encrypt(plaintext) {
  if (plaintext == null || plaintext === "") return null;
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(String(plaintext), "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  return `${iv.toString("hex")}:${authTag}:${encrypted}`;
}

function decrypt(encryptedText) {
  if (encryptedText == null || encryptedText === "") return null;
  try {
    const parts = String(encryptedText).split(":");
    if (parts.length !== 3) {
      return null; // Not in expected format, possibly old data or invalid
    }
    const [ivHex, authTagHex, encryptedDataHex] = parts;
    if (ivHex.length !== IV_LENGTH * 2 || authTagHex.length !== 32) {
      return null;
    }
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");
    const key = getEncryptionKey();
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedDataHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    return null;
  }
}

function hashEmail(email) {
  if (!email) return null;
  const emailStr = String(email).trim().toLowerCase();
  const key = getEncryptionKey();
  const hmac = crypto.createHmac("sha256", key);
  hmac.update(emailStr, "utf8");
  return hmac.digest("hex");
}

module.exports = { encrypt, decrypt, hashEmail, getEncryptionKey };
