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

import { pick, types } from '@react-native-documents/picker';
import { Buffer } from 'buffer';
import * as RNFS from 'react-native-fs';

import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes';

/* =====================================================
   CONSTANTS (MUST MATCH PYTHON)
===================================================== */
const SAMPLE_MESSAGE = 'Hello from React Native (Kyber + AES-GCM)!';

const HKDF_SALT = new Uint8Array(32); // 32 × 0x00
const HKDF_INFO = new Uint8Array(Buffer.from('AES-256-GCM', 'utf8'));

const KYBER_PUBLIC_KEY_SIZE = 1568;

/* =====================================================
   HELPERS
===================================================== */
const randomBytes = (n: number): Uint8Array => {
  const b = new Uint8Array(n);
  global.crypto.getRandomValues(b);
  return b;
};

const concatBytes = (...arrays: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(arrays.reduce((s, a) => s + a.length, 0));
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
};

const deriveAesKey = (sharedSecret: Uint8Array): Uint8Array =>
  hkdf(sha256, sharedSecret, HKDF_SALT, HKDF_INFO, 32);

const stringToBytes = (s: string): Uint8Array =>
  new Uint8Array(Buffer.from(s, 'utf8'));

const hex = (b: Uint8Array): string =>
  Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

const preview = (b: Uint8Array, n = 16): string =>
  hex(b.slice(0, n)) + ' …';

/* =====================================================
   FILE HELPERS
===================================================== */
const getDownloadDir = () =>
  Platform.OS === 'android'
    ? RNFS.DownloadDirectoryPath
    : RNFS.DocumentDirectoryPath;

const requestAndroidPermission = async () => {
  if (Platform.OS !== 'android') return true;
  const granted = await PermissionsAndroid.request(
    PermissionsAndroid.PERMISSIONS.WRITE_EXTERNAL_STORAGE,
  );
  return granted === PermissionsAndroid.RESULTS.GRANTED;
};

const writeBinaryFile = async (
  filename: string,
  bytes: Uint8Array,
): Promise<string> => {
  const path = `${getDownloadDir()}/${filename}`;
  await RNFS.writeFile(
    path,
    Buffer.from(bytes).toString('base64'),
    'base64',
  );
  return path;
};

const readBin = async (uri: string): Promise<Uint8Array> =>
  new Uint8Array(
    Buffer.from(await RNFS.readFile(uri, 'base64'), 'base64'),
  );

/* =====================================================
   OPTIONAL BASE64 FALLBACK (DEV ONLY)
===================================================== */
const PUBLIC_KEY_B64: string | null = null;
const decodeBase64Key = (b64: string) =>
  new Uint8Array(Buffer.from(b64, 'base64'));

/* =====================================================
   SCREEN
===================================================== */
export default function PqcEncryptScreen() {
  const [log, setLog] = useState('');

  const logIt = (m: string) => {
    console.log(m);
    setLog(prev => prev + m + '\n');
  };

  const block = (title: string) => {
    logIt('\n' + '='.repeat(70));
    logIt(title);
    logIt('='.repeat(70));
  };

  useEffect(() => {
    (async () => {
      try {
        if (!(await requestAndroidPermission())) {
          Alert.alert('Permission denied', 'Storage permission required');
          return;
        }

        logIt('🚀 PQC Encryption — ML-KEM-1024 + AES-256-GCM');

        /* =================================================
           STEP 1: PUBLIC KEY
        ================================================= */
        block('STEP 1: PUBLIC KEY LOADING');

        let publicKey: Uint8Array | null = null;

        try {
          logIt('• Opening file picker');
          const [file] = await pick({ type: [types.allFiles] });
          const uri = (file as any).fileCopyUri ?? file.uri;
          publicKey = await readBin(uri);
          logIt('• Source              : File picker');
        } catch {
          logIt('• Picker skipped');
        }

        if (!publicKey) {
          if (!PUBLIC_KEY_B64) {
            throw new Error('No public key provided');
          }
          publicKey = decodeBase64Key(PUBLIC_KEY_B64);
          logIt('• Source              : Base64 fallback');
        }

        logIt(`• Public key size     : ${publicKey.length} bytes`);
        logIt(`• Public key preview  : ${preview(publicKey)}`);
        logIt(`• Public key SHA256   : ${hex(sha256(publicKey))}`);

        if (publicKey.length !== KYBER_PUBLIC_KEY_SIZE) {
          throw new Error('Invalid ML-KEM-1024 public key size');
        }

        /* =================================================
           STEP 2: ML-KEM ENCAPSULATION
        ================================================= */
        block('STEP 2: ML-KEM-1024 ENCAPSULATION');

        const { cipherText, sharedSecret } =
          ml_kem1024.encapsulate(publicKey);

        logIt(`• Kyber ciphertext size : ${cipherText.length}`);
        logIt(`• Kyber CT preview      : ${preview(cipherText)}`);
        logIt(`• Shared secret size    : ${sharedSecret.length}`);
        logIt(`• Shared secret preview : ${preview(sharedSecret)}`);
        logIt(`• Shared secret SHA256  : ${hex(sha256(sharedSecret))}`);

        /* =================================================
           STEP 3: HKDF
        ================================================= */
        block('STEP 3: HKDF-SHA256');

        logIt(`• HKDF salt            : ${hex(HKDF_SALT)}`);
        logIt(`• HKDF info            : ${Buffer.from(HKDF_INFO).toString('utf8')}`);

        const aesKey = deriveAesKey(sharedSecret);

        logIt(`• AES key size         : ${aesKey.length}`);
        logIt(`• AES key preview      : ${preview(aesKey)}`);
                logIt(`• AES key preview      : ${aesKey}`);

        logIt(`• AES key SHA256       : ${hex(sha256(aesKey))}`);

        /* =================================================
           STEP 4: AES-GCM
        ================================================= */
        block('STEP 4: AES-256-GCM ENCRYPTION');

        const nonce = randomBytes(12);
        const plaintext = stringToBytes(SAMPLE_MESSAGE);
        const encrypted = gcm(aesKey, nonce).encrypt(plaintext);

        const aesCiphertext = encrypted.slice(0, -16);
        const tag = encrypted.slice(-16);

        logIt(`• Plaintext            : "${SAMPLE_MESSAGE}"`);
        logIt(`• Plaintext size       : ${plaintext.length}`);
        logIt(`• Nonce                : ${hex(nonce)}`);
        logIt(`• Ciphertext size      : ${aesCiphertext.length}`);
        logIt(`• Ciphertext preview   : ${hex(aesCiphertext)}`);
        logIt(`• Auth tag             : ${hex(tag)}`);

        /* =================================================
           STEP 5: PACKET ASSEMBLY (CRITICAL)
        ================================================= */
        block('STEP 5: PACKET ASSEMBLY');

        const packet = concatBytes(
          cipherText, // 1568
          nonce,      // 12
          encrypted,  // ciphertext + tag
        );

        logIt('• Packet layout        : [ kyber_ct | nonce | aes_cipher+tag ]');
        logIt(`• Offset 0             : Kyber ciphertext`);
        logIt(`• Offset 1568          : Nonce`);
        logIt(`• Offset 1580          : AES ciphertext`);
        logIt(`• Last 16 bytes        : AES-GCM tag`);
        logIt(`• Packet total size    : ${packet.length}`);
        logIt(`• Packet SHA256        : ${hex(sha256(packet))}`);

        /* =================================================
           STEP 6: FILE OUTPUT
        ================================================= */
        block('STEP 6: FILE OUTPUT');

        const ts = Date.now();
        const pubKeyPath = await writeBinaryFile(
          `${ts}_kyber_public.bin`,
          publicKey,
        );
        const packetPath = await writeBinaryFile(
          `${ts}_encrypted_packet.bin`,
          packet,
        );

        logIt(`• Public key file      : ${pubKeyPath}`);
        logIt(`• Encrypted packet     : ${packetPath}`);
        logIt(`• Python input file    : encrypted_packet.bin`);

        Alert.alert('Success ✅', 'Encryption complete');
      } catch (e: any) {
        logIt(`❌ ERROR: ${e.message}`);
        Alert.alert('Error ❌', e.message);
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
