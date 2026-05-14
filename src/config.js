import 'dotenv/config';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, '..');
const IS_VERCEL = process.env.VERCEL === '1' || process.env.VERCEL === 'true';

export const PORT = process.env.PORT || 3000;

// ─── ECDSA P-256 keypair (persisted to keypair.json) ───

const KEYPAIR_FILE = path.join(ROOT_DIR, 'keypair.json');

const parseJsonEnv = (...names) => {
  for (const name of names) {
    const value = process.env[name];
    if (!value) continue;
    try {
      return JSON.parse(value);
    } catch {
      try {
        return JSON.parse(Buffer.from(value, 'base64').toString('utf8'));
      } catch {
        throw new Error(`${name} must be JSON or base64-encoded JSON`);
      }
    }
  }
  return null;
};

const createEcKeyPair = (saved) => ({
  privateKey: crypto.createPrivateKey({ key: Buffer.from(saved.privateKey, 'base64'), format: 'der', type: 'pkcs8' }),
  publicKey: crypto.createPublicKey({ key: Buffer.from(saved.publicKey, 'base64'), format: 'der', type: 'spki' }),
});

const exportEcKeyPair = (keyPair) => ({
  privateKey: keyPair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  publicKey: keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
});

const loadEcKeyPair = () => {
  const fromEnv = parseJsonEnv('KASPI_KEYPAIR_JSON', 'KASPI_KEYPAIR_JSON_BASE64', 'KEYPAIR_JSON', 'KEYPAIR_JSON_BASE64');
  if (fromEnv) {
    console.log('Loaded ECDSA keypair from environment');
    return createEcKeyPair(fromEnv);
  }

  if (fs.existsSync(KEYPAIR_FILE)) {
    const saved = JSON.parse(fs.readFileSync(KEYPAIR_FILE, 'utf8'));
    console.log('Loaded ECDSA keypair from keypair.json');
    return createEcKeyPair(saved);
  }

  const generated = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const saved = exportEcKeyPair(generated);

  if (IS_VERCEL) {
    console.warn('Generated ephemeral ECDSA keypair. Set KASPI_KEYPAIR_JSON in Vercel for stable sessions.');
  } else {
    fs.writeFileSync(KEYPAIR_FILE, JSON.stringify(saved, null, 2));
    console.log('Generated new ECDSA keypair -> saved to keypair.json');
  }

  return generated;
};

const ecKeyPair = loadEcKeyPair();

export { ecKeyPair };

// Uncompressed EC public key point (base64)
const pubKeyDer = ecKeyPair.publicKey.export({ type: 'spki', format: 'der' });
const x509B64 = pubKeyDer.toString('base64');
const uncompressedPoint = pubKeyDer.slice(pubKeyDer.length - 65);
const pkB64 = uncompressedPoint.toString('base64');
const pkTagHash = crypto.createHash('md5').update(pkB64).digest('hex');

// ─── Device identity (persisted to device.json) ───

const DEVICE_FILE = path.join(ROOT_DIR, 'device.json');

const loadDevice = () => {
  const fromEnv = parseJsonEnv('KASPI_DEVICE_JSON', 'KASPI_DEVICE_JSON_BASE64', 'DEVICE_JSON', 'DEVICE_JSON_BASE64');
  if (fromEnv) {
    console.log('Loaded device identity from environment');
    return fromEnv;
  }

  if (process.env.KASPI_DEVICE_ID && process.env.KASPI_INSTALL_ID && process.env.KASPI_PIN_HASH) {
    console.log('Loaded device identity from split environment variables');
    return {
      deviceId: process.env.KASPI_DEVICE_ID,
      installId: process.env.KASPI_INSTALL_ID,
      pinHash: process.env.KASPI_PIN_HASH,
    };
  }

  if (fs.existsSync(DEVICE_FILE)) {
    console.log('Loaded device identity from device.json');
    return JSON.parse(fs.readFileSync(DEVICE_FILE, 'utf8'));
  }

  const generated = {
    deviceId: crypto.randomUUID().toUpperCase(),
    installId: crypto.randomUUID().toUpperCase(),
    pinHash: crypto.createHash('md5').update(crypto.randomBytes(16)).digest('hex'),
  };

  if (IS_VERCEL) {
    console.warn('Generated ephemeral device identity. Set KASPI_DEVICE_JSON in Vercel for stable sessions.');
  } else {
    fs.writeFileSync(DEVICE_FILE, JSON.stringify(generated, null, 2));
    console.log('Generated new device identity -> saved to device.json');
  }

  return generated;
};

const { deviceId, installId, pinHash } = loadDevice();

export const DEVICE = {
  deviceId,
  installId,
  pk: pkB64,
  pkTag: pkTagHash,
  pinHash,
  x509: x509B64,
};

console.log('  pk:', DEVICE.pk);
console.log('  x509:', DEVICE.x509);
console.log('  pkTag:', DEVICE.pkTag);

// ─── Kaspi Base URLs ───

export const KASPI_ENTRANCE_URL = 'https://entrance-pay.kaspi.kz';
export const KASPI_MTOKEN_URL = 'https://mtoken.kaspi.kz';
export const KASPI_QRPAY_URL = 'https://qrpay.kaspi.kz';

// ─── App version & device constants ───
// These values are hardcoded intentionally: the Kaspi API validates device
// parameters and may reject requests with arbitrary or unknown values.

export const APP = {
  version: '4.105',
  build: '1070',
  platform: 'iOS',
  platformVer: '18.5',
  locale: 'ru-RU',
  model: 'iPhone17,3',
  brand: 'Apple',
  deviceName: 'iPhone',
  screenW: '393.0',
  screenH: '852.0',
  cfNetwork: 'CFNetwork/3826.500.131',
  darwin: 'Darwin/24.5.0',
};

export const UA_NATIVE = `Kaspi%20Pay/${APP.build} ${APP.cfNetwork} ${APP.darwin}`;
export const UA_BROWSER = `Mozilla/5.0 (iPhone; CPU iPhone OS ${APP.platformVer.replace('.', '_')} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148`;

export const ENTRANCE_HEADERS_BASE = {
  Accept: 'application/json, text/plain, */*',
  'Content-Type': 'application/json',
  'Accept-Language': 'ru',
  'Accept-Encoding': 'gzip, deflate, br',
  Origin: KASPI_ENTRANCE_URL,
  'Sec-Fetch-Site': 'same-origin',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Dest': 'empty',
  'User-Agent': UA_BROWSER,
};

export { ROOT_DIR };
