// MUST be first — required for PQC randomness
import 'react-native-get-random-values';

import React, { useEffect, useState } from 'react';
import {
  SafeAreaView,
  ScrollView,
  Text,
  StyleSheet,
  Platform,
  Alert,
  PermissionsAndroid,
} from 'react-native';

import { Buffer } from 'buffer';
import * as RNFS from 'react-native-fs';

import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes';

/* =====================================================
   RN-SAFE RANDOM BYTES
===================================================== */
const randomBytes = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  if (global.crypto?.getRandomValues) {
    global.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return bytes;
};

/* =====================================================
   CONSTANTS (MATCH PYTHON)
===================================================== */
const SAMPLE_MESSAGE = 'Hello from React Native (Kyber + AES-GCM)!';
const HKDF_SALT = new Uint8Array(32);
const HKDF_INFO = new TextEncoder().encode('AES-256-GCM');

/* =====================================================
   HELPERS
===================================================== */
const concatBytes = (...arrays: Uint8Array[]) => {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
};

const deriveAesKey = (sharedSecret: Uint8Array) =>
  hkdf(sha256, sharedSecret, HKDF_SALT, HKDF_INFO, 32);

const stringToBytes = (str: string): Uint8Array =>
  new Uint8Array(Buffer.from(str, 'utf8'));

/* =====================================================
   FILE HELPERS
===================================================== */

const isoTimestamp = () =>
  new Date().toISOString().replace(/:/g, '-').replace('T', '_').split('.')[0];

const getDownloadDir = () => {
  if (Platform.OS === 'android') {
    return RNFS.DownloadDirectoryPath;
  }
  return RNFS.DocumentDirectoryPath;
};

const requestAndroidPermission = async () => {
  if (Platform.OS !== 'android') return true;
  const granted = await PermissionsAndroid.request(
    PermissionsAndroid.PERMISSIONS.WRITE_EXTERNAL_STORAGE,
  );
  return granted === PermissionsAndroid.RESULTS.GRANTED;
};

const writeBinaryFile = async (filename: string, bytes: Uint8Array) => {
  const dir = getDownloadDir();
  const path = `${dir}/${filename}`;
  const base64 = Buffer.from(bytes).toString('base64');
  await RNFS.writeFile(path, base64, 'base64');
  return path;
};

/* =====================================================
   SCREEN
===================================================== */

const PUBLIC_KEY_B64 = null; // e.g., 'AAECAwQ...'

const decodeBase64Key = b64 => new Uint8Array(Buffer.from(b64, 'base64'));

export default function PqcEncryptScreen() {
  const [log, setLog] = useState('');

  useEffect(() => {
    (async () => {
      try {
        if (!(await requestAndroidPermission())) {
          Alert.alert('Permission denied', 'Storage permission required');
          return;
        }

        const L: string[] = [];
        const logIt = (m: string) => {
          console.log(m);
          L.push(m);
        };

        logIt('🚀 PQC Encryption — ML-KEM-1024 + AES-256-GCM');
        logIt('================================================');

        /* ---------- 1️⃣ LOAD OR GENERATE PUBLIC KEY ---------- */

        let publicKey: Uint8Array;

        if (PUBLIC_KEY_B64) {
          publicKey = decodeBase64Key(PUBLIC_KEY_B64);

          if (publicKey.length !== 1568) {
            throw new Error(
              `Invalid public key length: ${publicKey.length} bytes (expected 1568)`,
            );
          }

          logIt(`✓ Loaded public key from Base64 (${publicKey.length} bytes)`);
        } else {
          const keypair = ml_kem1024.keygen();
          publicKey = keypair.publicKey;

          logIt('⚠️ PUBLIC_KEY_B64 not set — generated demo keypair');
          logIt(`✓ Generated public key: ${publicKey.length} bytes`);
        }

        /* ---------- 2️⃣ ENCAPSULATION ---------- */
        const { cipherText, sharedSecret } = ml_kem1024.encapsulate(publicKey);

        /* ---------- 3️⃣ HKDF ---------- */
        const aesKey = deriveAesKey(sharedSecret);

        /* ---------- 4️⃣ AES-GCM ---------- */
        const nonce = randomBytes(12);
        const plaintextBytes = stringToBytes(SAMPLE_MESSAGE);

        const cipher = gcm(aesKey, nonce);
        const encrypted = cipher.encrypt(plaintextBytes);

        /* ---------- 5️⃣ FINAL PACKET ---------- */
        const packet = concatBytes(cipherText, nonce, encrypted);

        /* ---------- 6️⃣ SAVE FILES ---------- */
        const ts = isoTimestamp();

        const pubKeyPath = await writeBinaryFile(
          `${ts}_kyber_public.key`,
          publicKey,
        );

        const packetPath = await writeBinaryFile(
          `${ts}_encrypted_packet.bin`,
          packet,
        );

        logIt('✅ FILES SAVED FOR PYTHON');
        logIt(`Public key: ${pubKeyPath}`);
        logIt(`Encrypted packet: ${packetPath}`);

        setLog(L.join('\n'));

        Alert.alert(
          'Success ✅',
          `Files saved successfully:\n\n${pubKeyPath}\n${packetPath}`,
        );
      } catch (e: any) {
        Alert.alert('Error ❌', e.message);
        setLog(`❌ ERROR\n${e.message}\n${e.stack ?? ''}`);
      }
    })();
  }, []);

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView>
        <Text style={styles.mono}>{log}</Text>
      </ScrollView>
    </SafeAreaView>
  );
}

/* =====================================================
   STYLES
===================================================== */
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0b1224',
    padding: 16,
  },
  mono: {
    color: '#e8f0ff',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    fontSize: 13,
    lineHeight: 20,
  },
});
