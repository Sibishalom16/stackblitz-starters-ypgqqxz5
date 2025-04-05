require('dotenv').config();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// --- ENV VARIABLES ---
const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Must be 32 bytes
const IV_LENGTH = 16;

// --- ENCRYPT FUNCTION ---
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// --- DECRYPT FUNCTION ---
function decrypt(text) {
  const [ivHex, encryptedHex] = text.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encryptedText = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// --- JWT GENERATION ---
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

// --- JWT VERIFICATION ---
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

// --- DEMO FLOW ---
const payload = { userId: 123, role: 'admin' };

// Step 1: Generate JWT
const token = generateToken(payload);
console.log('Original JWT:', token);

// Step 2: Encrypt JWT
const encryptedToken = encrypt(token);
console.log('Encrypted JWT:', encryptedToken);

// Step 3: Decrypt JWT
const decryptedToken = decrypt(encryptedToken);
console.log('Decrypted JWT:', decryptedToken);

// Step 4: Verify Decrypted JWT
try {
  const decoded = verifyToken(decryptedToken);
  console.log('✅ Success! Decoded Payload:', decoded);
} catch (error) {
  console.error('❌ Decryption Failed:', error.message);
}
