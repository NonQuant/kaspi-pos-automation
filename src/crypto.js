import crypto from 'crypto';
import {ecKeyPair} from './config.js';

// ─── ECDH ───

const vtokenSuite = 'OCRA-1:HOTP-SHA256-6:QH64-T1M';

// ─── AES-256-GCM encryption for vtokenSecret ───

const getEncryptionKey = () => {
  const key = process.env.TOKEN_SECRET_KEY || '';
  if (!/^[0-9a-fA-F]{64}$/.test(key)) {
    throw new Error('TOKEN_SECRET_KEY must be set to a 64-character hex string');
  }
  return Buffer.from(key, 'hex');
};

export const encryptSecret = (secretBuffer) => {
  const iv = crypto.randomBytes(12);
  const ENCRYPTION_KEY = getEncryptionKey();
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(secretBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
};

export const decryptSecret = (tokenB64) => {
  const buf = Buffer.from(tokenB64, 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const ENCRYPTION_KEY = getEncryptionKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
};

export const encryptJson = (value) => encryptSecret(Buffer.from(JSON.stringify(value), 'utf8'));

export const decryptJson = (tokenB64) => JSON.parse(decryptSecret(tokenB64).toString('utf8'));

let lastEcdhKeyPair = null;

const serializeEcdhKeyPair = (keyPair) => ({
  privateKey: keyPair.privateKey.export({type: 'pkcs8', format: 'der'}).toString('base64'),
  publicKey: keyPair.publicKey.export({type: 'spki', format: 'der'}).toString('base64'),
});

const deserializeEcdhPrivateKey = (saved) =>
  crypto.createPrivateKey({
    key: Buffer.from(saved.privateKey, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });

export const generateECDH = () => {
  lastEcdhKeyPair = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
  const spki = lastEcdhKeyPair.publicKey.export({type: 'spki', format: 'der'});
  return spki.toString('base64');
};

export const exportLastECDH = () => {
  if (!lastEcdhKeyPair) return null;
  return encryptJson(serializeEcdhKeyPair(lastEcdhKeyPair));
};

export const completeECDH = (serverX509B64) => {
  if (!lastEcdhKeyPair) throw new Error('No ECDH keypair generated');
  const serverPubKey = crypto.createPublicKey({
    key: Buffer.from(serverX509B64, 'base64'),
    format: 'der',
    type: 'spki',
  });
  const secret = crypto.diffieHellman({
    privateKey: lastEcdhKeyPair.privateKey,
    publicKey: serverPubKey,
  });
  console.log('ECDH shared secret derived, length:', secret.length);
  lastEcdhKeyPair = null;
  return secret;
};

export const completeECDHWithSaved = (serverX509B64, savedState) => {
  if (!savedState) throw new Error('No saved ECDH keypair state provided');
  const saved = decryptJson(savedState);
  const privateKey = deserializeEcdhPrivateKey(saved);
  const serverPubKey = crypto.createPublicKey({
    key: Buffer.from(serverX509B64, 'base64'),
    format: 'der',
    type: 'spki',
  });
  const secret = crypto.diffieHellman({privateKey, publicKey: serverPubKey});
  console.log('ECDH (saved key) shared secret derived, length:', secret.length);
  return secret;
};

// ─── Helpers ───

const hexToBytes = (hex) => {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return Buffer.from(bytes);
};

// ─── OCRA-1 TOTP (matches Kaspi vtoken) ───

export const computeTokenSnMac = (tokenSN, secret) => {
  if (!secret) return '000000';

  const timeStep = BigInt(Date.now()) / BigInt(30000);
  const timeHex = timeStep.toString(16);

  const qHex = Buffer.from(tokenSN || '00000000')
    .toString('hex')
    .substring(0, 64);

  const suiteBytes = Buffer.from(vtokenSuite);
  const separator = Buffer.from([0x00]);

  const qPadded = qHex.padEnd(256, '0');
  const qBytes = hexToBytes(qPadded);

  const tPadded = timeHex.padStart(16, '0');
  const tBytes = hexToBytes(tPadded);

  const dataBuffer = Buffer.concat([suiteBytes, separator, qBytes, tBytes]);

  const hash = crypto.createHmac('sha256', secret).update(dataBuffer).digest();

  // Dynamic truncation (RFC 4226)
  const offset = hash[hash.length - 1] & 0x0f;
  const binCode =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  return (binCode % 1000000).toString().padStart(6, '0');
};

// ─── ECDSA signing ───

export const ecSign = (data) => {
  const sign = crypto.createSign('SHA256');
  sign.update(data);
  sign.end();
  return sign.sign(ecKeyPair.privateKey).toString('base64');
};

export const signDataPayload = (dataB64) => ecSign(dataB64);

export const computeXSU = (url) => crypto.createHash('md5').update(url.toLowerCase()).digest('hex');

export const computeXSign = (url, headers, xshList) => {
  const parts = xshList.split(',').map((name) => {
    if (name === 'url') {
      try {
        const u = new URL(url);
        return u.pathname + u.search;
      } catch {
        return url;
      }
    }
    return headers[name] || '';
  });
  return ecSign(parts.join(''));
};
