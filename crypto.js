import 'react-native-get-random-values';
import { Buffer } from 'buffer';
import { kyber1024 } from '@noble/post-quantum/kyber';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@stablelib/random';
import { AESGCM } from '@stablelib/aes-gcm';

// HKDF parameters (must match .NET and Python)
const HKDF_SALT = new Uint8Array(32); // 32 zero bytes
const HKDF_INFO = new TextEncoder().encode('AES-256-GCM');

const concatBytes = (...arrays) => {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
};

const deriveAesKey = (sharedSecret) => {
  // HKDF-SHA256(sharedSecret, salt=32x0, info="AES-256-GCM", len=32)
  return hkdf(sha256, sharedSecret, HKDF_SALT, HKDF_INFO, 32);
};

export const encryptHybrid = ({ publicKeyBytes, plaintextBytes }) => {
  if (!publicKeyBytes || publicKeyBytes.length !== 1568) {
    throw new Error('Public key must be 1568 bytes (Kyber1024 pk)');
  }

  // 1) Encapsulate
  const { ciphertext: kyberCiphertext, sharedSecret } = kyber1024.encapsulate(publicKeyBytes);

  // 2) Derive AES-256 key via HKDF-SHA256
  const aesKey = deriveAesKey(sharedSecret);

  // 3) Encrypt with AES-256-GCM
  const nonce = randomBytes(12);
  const aes = new AESGCM(aesKey);
  const aesEncrypted = aes.seal(nonce, plaintextBytes); // ciphertext || tag (16 bytes)

  // 4) Packet: [Kyber CT:1568][Nonce:12][Ciphertext||Tag]
  const packet = concatBytes(kyberCiphertext, nonce, aesEncrypted);

  return {
    packet,
    kyberCiphertext,
    sharedSecret,
    aesKey,
    nonce,
    aesEncrypted,
  };
};

export const decodeBase64Key = (b64) => new Uint8Array(Buffer.from(b64, 'base64'));
export const encodeBase64 = (bytes) => Buffer.from(bytes).toString('base64');