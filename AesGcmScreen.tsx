import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  ScrollView,
  StyleSheet,
  Alert,
  Platform,
  PermissionsAndroid,
} from 'react-native';
import { gcm } from '@noble/ciphers/aes';
import * as RNFS from 'react-native-fs';
import { pick, types, errorCodes, isErrorWithCode } from '@react-native-documents/picker';

// Polyfill for React Native if needed
if (typeof global.crypto === 'undefined') {
  // @ts-ignore
  global.crypto = {
    getRandomValues: (arr: Uint8Array) => {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = Math.floor(Math.random() * 256);
      }
      return arr;
    },
  };
}

// Random bytes generator for React Native
const randomBytes = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return bytes;
};

// Base64 utilities
const bytesToBase64 = (bytes: Uint8Array): string => {
  const binary = Array.from(bytes)
    .map((b) => String.fromCharCode(b))
    .join('');
  return btoa(binary);
};

const base64ToBytes = (base64: string): Uint8Array => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const bytesToHex = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

// Text encoding/decoding
const stringToBytes = (str: string): Uint8Array => {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
};

const bytesToString = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map((b) => String.fromCharCode(b))
    .join('');
};

// Build .bin format => [12-byte nonce][ciphertext+tag]
const buildBinFile = (nonce: Uint8Array, ciphertextAndTag: Uint8Array): Uint8Array => {
  const result = new Uint8Array(nonce.length + ciphertextAndTag.length);
  result.set(nonce, 0);
  result.set(ciphertextAndTag, nonce.length);
  return result;
};

// Parse .bin bytes => nonce, ciphertext, tag
const parseBinBytes = (bytes: Uint8Array) => {
  if (bytes.length < 12 + 16) {
    throw new Error('Invalid .bin data: too small');
  }

  const nonce = bytes.slice(0, 12);
  const ciphertextAndTag = bytes.slice(12);
  const tag = ciphertextAndTag.slice(ciphertextAndTag.length - 16);
  const ciphertext = ciphertextAndTag.slice(0, ciphertextAndTag.length - 16);

  return {
    nonce,
    ciphertext,
    tag,
    ciphertextAndTag,
  };
};

// AES-256-GCM encryption using @noble/ciphers
const gcmEncrypt = (
  plaintext: string,
  keyBytes: Uint8Array,
  nonceBytes: Uint8Array
): { combined: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array } => {
  console.log('\n========== ENCRYPTION STARTED ==========');

  const data = stringToBytes(plaintext);

  // Create GCM cipher instance
  const cipher = gcm(keyBytes, nonceBytes);

  // Encrypt (returns ciphertext + 16-byte authentication tag appended)
  const encrypted = cipher.encrypt(data);

  // Extract tag (last 16 bytes)
  const tagLength = 16;
  const ciphertext = encrypted.slice(0, encrypted.length - tagLength);
  const tag = encrypted.slice(encrypted.length - tagLength);

  console.log('\n========== ENCRYPTION COMPLETED ==========\n');

  return {
    combined: encrypted,
    ciphertext: ciphertext,
    tag: tag,
  };
};

const gcmDecrypt = (
  ciphertextWithTag: Uint8Array,
  keyBytes: Uint8Array,
  nonceBytes: Uint8Array
): Uint8Array => {
  console.log('\n========== DECRYPTION STARTED ==========');

  // Decrypt (automatically verifies authentication tag)
  const cipher = gcm(keyBytes, nonceBytes);
  const decrypted = cipher.decrypt(ciphertextWithTag);

  console.log('\n========== DECRYPTION COMPLETED ==========\n');

  return decrypted;
};

// Request Android storage permissions for Downloads folder
const requestStoragePermissions = async (): Promise<boolean> => {
  if (Platform.OS !== 'android') return true;

  try {
    const apiLevel = Platform.Version;
    
    if (apiLevel >= 30) {
      // Android 11+ (API 30+) - requires MANAGE_EXTERNAL_STORAGE
      // Note: This permission must be granted manually in app settings
      // We'll try to save to Downloads and handle the error if permission is missing
      return true;
    } else {
      // Android 10 and below
      const granted = await PermissionsAndroid.request(
        PermissionsAndroid.PERMISSIONS.WRITE_EXTERNAL_STORAGE,
        {
          title: 'Storage Permission',
          message: 'This app needs access to your storage to save encrypted files in Downloads.',
          buttonPositive: 'OK',
        }
      );
      
      return granted === PermissionsAndroid.RESULTS.GRANTED;
    }
  } catch (err) {
    console.log('⚠️ Error requesting storage permission:', err);
    return false;
  }
};

// Save file to Downloads folder
const saveToDownloads = async (filename: string, base64Data: string): Promise<string | null> => {
  try {
    if (Platform.OS === 'android') {
      // Try to save to Downloads folder
      let downloadsPath = RNFS.DownloadDirectoryPath;
      
      // Fallback if DownloadDirectoryPath doesn't exist
      if (!downloadsPath) {
        downloadsPath = RNFS.ExternalStorageDirectoryPath + '/Download';
      }
      
      const filePath = `${downloadsPath}/${filename}`;
      
      console.log(`📁 Saving to Downloads: ${filePath}`);
      
      // Check if file exists, if yes, add timestamp
      const exists = await RNFS.exists(filePath);
      let finalPath = filePath;
      
      if (exists) {
        const timestamp = Date.now();
        const newFilename = `encrypted_${timestamp}.bin`;
        finalPath = `${downloadsPath}/${newFilename}`;
        console.log(`📁 File exists, saving as: ${newFilename}`);
      }
      
      // Write the file
      await RNFS.writeFile(finalPath, base64Data, 'base64');
      console.log(`✅ File saved successfully to: ${finalPath}`);
      
      // Update media scanner to recognize the file
      if (Platform.OS === 'android') {
        await RNFS.scanFile(finalPath);
      }
      
      return finalPath;
    } else {
      // For iOS, use DocumentDirectory (iOS restricts direct Downloads access)
      const docsPath = RNFS.DocumentDirectoryPath;
      const filePath = `${docsPath}/${filename}`;
      await RNFS.writeFile(filePath, base64Data, 'base64');
      console.log(`✅ File saved to iOS Documents: ${filePath}`);
      return filePath;
    }
  } catch (error) {
    console.error('❌ Error saving to Downloads:', error);
    
    // Fallback: Save to app's private directory
    try {
      const privatePath = RNFS.DocumentDirectoryPath;
      const fallbackPath = `${privatePath}/${filename}`;
      await RNFS.writeFile(fallbackPath, base64Data, 'base64');
      console.log(`✅ File saved to fallback location: ${fallbackPath}`);
      return fallbackPath;
    } catch (fallbackError) {
      console.error('❌ Fallback save also failed:', fallbackError);
      return null;
    }
  }
};

const AesGcmScreen = () => {
  const [mode, setMode] = useState<'encrypt' | 'decrypt'>('encrypt');
  const [inputText, setInputText] = useState('');
  const [key, setKey] = useState('');
  const [nonce, setNonce] = useState('');
  const [output, setOutput] = useState('');
  const [tagDisplay, setTagDisplay] = useState('');
  const [binOutput, setBinOutput] = useState('');
  const [binFilePath, setBinFilePath] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);

  const validateKey = (keyInput: string): boolean => {
    try {
      const decoded = base64ToBytes(keyInput);
      return decoded.length === 32;
    } catch (e) {
      return false;
    }
  };

  const validateNonce = (nonceInput: string): boolean => {
    try {
      const decoded = base64ToBytes(nonceInput);
      return decoded.length === 12;
    } catch (e) {
      return false;
    }
  };

  const generateRandomKey = () => {
    const keyBytes = randomBytes(32);
    const base64Key = bytesToBase64(keyBytes);
    setKey(base64Key);
  };

  const generateRandomNonce = () => {
    const nonceBytes = randomBytes(12);
    const base64Nonce = bytesToBase64(nonceBytes);
    setNonce(base64Nonce);
  };

  const handleImportBin = async () => {
    try {
      const [file] = await pick({
        type: [types.allFiles],
      });

      if (!file) {
        return;
      }

      const uri = (file as any).fileCopyUri ?? file.uri;

      // Read file as base64, convert to bytes
      const fileBase64 = await RNFS.readFile(uri, 'base64');
      const fileBytes = base64ToBytes(fileBase64);

      const parsed = parseBinBytes(fileBytes);

      const nonceB64 = bytesToBase64(parsed.nonce);
      const ctPlusTagB64 = bytesToBase64(parsed.ciphertextAndTag);
      const tagB64 = bytesToBase64(parsed.tag);
      const tagHex = bytesToHex(parsed.tag);

      // Switch to decrypt mode because .bin implies encrypted input
      setMode('decrypt');
      setNonce(nonceB64);
      setInputText(ctPlusTagB64);
      setOutput('');
      setBinOutput(fileBase64);
      setBinFilePath(uri);
      setTagDisplay(
        `Extracted from .bin:\n` +
          `Nonce (Base64): ${nonceB64}\n` +
          `Tag (Base64): ${tagB64}\nTag (Hex): ${tagHex}\n\n` +
          `Ciphertext+Tag Length: ${parsed.ciphertextAndTag.length} bytes`
      );

      Alert.alert('Success', '.bin file loaded and parsed successfully');
    } catch (err: any) {
      if (isErrorWithCode(err) && err.code === errorCodes.OPERATION_CANCELED) {
        return;
      }
      Alert.alert('Error', err.message || 'Failed to import .bin file');
    }
  };

  const saveEncryptedFile = async (binBase64: string) => {
    try {
      const timestamp = Date.now();
      const filename = `encrypted_${timestamp}.bin`;
      
      // For Android, ask for permissions first
      if (Platform.OS === 'android') {
        const hasPermission = await requestStoragePermissions();
        if (!hasPermission) {
          Alert.alert(
            'Permission Required',
            'Storage permission is required to save files to Downloads folder.',
            [
              { text: 'Cancel', style: 'cancel' },
              { 
                text: 'Try Again', 
                onPress: () => saveEncryptedFile(binBase64)
              }
            ]
          );
          return null;
        }
      }
      
      const savedPath = await saveToDownloads(filename, binBase64);
      
      if (savedPath) {
        setBinFilePath(savedPath);
        
        // Show success message with file path
        const displayPath = savedPath.split('/').pop() || filename;
        Alert.alert(
          'File Saved Successfully!',
          `Encrypted .bin file saved as:\n${displayPath}\n\nLocation: ${savedPath}`
        );
        
        return savedPath;
      } else {
        Alert.alert('Error', 'Failed to save the encrypted file.');
        return null;
      }
    } catch (error: any) {
      Alert.alert('Error', error.message || 'Failed to save the encrypted file.');
      return null;
    }
  };

  const handleProcess = async () => {
    if (!inputText.trim()) {
      Alert.alert('Error', `Please enter text to ${mode}`);
      return;
    }

    if (!validateKey(key)) {
      Alert.alert('Error', 'Key must be a valid Base64 string representing 32 bytes (256 bits)');
      return;
    }

    if (!validateNonce(nonce)) {
      Alert.alert('Error', 'Nonce/IV must be a valid Base64 string representing 12 bytes (96 bits)');
      return;
    }

    setIsProcessing(true);
    setOutput('');
    setTagDisplay('');
    setBinOutput('');
    setBinFilePath('');

    try {
      let processedKey = base64ToBytes(key);
      let processedNonce = base64ToBytes(nonce);

      // Ensure exactly 32-byte key
      if (processedKey.length !== 32) {
        const fullKey = new Uint8Array(32);
        fullKey.set(processedKey.slice(0, 32));
        processedKey = fullKey;
      }

      // Ensure exactly 12-byte nonce
      if (processedNonce.length !== 12) {
        const fullNonce = new Uint8Array(12);
        fullNonce.set(processedNonce.slice(0, 12));
        processedNonce = fullNonce;
      }

      if (mode === 'encrypt') {
        const result = gcmEncrypt(inputText, processedKey, processedNonce);

        const base64Output = bytesToBase64(result.combined);
        setOutput(base64Output);

        const tagBase64 = bytesToBase64(result.tag);
        const tagHex = bytesToHex(result.tag);
        setTagDisplay(
          `Base64: ${tagBase64}\nHex: ${tagHex}\n\n✓ Tag is automatically appended to ciphertext`
        );

        // Build .bin = [nonce][ciphertext+tag]
        const binBytes = buildBinFile(processedNonce, result.combined);
        const binBase64 = bytesToBase64(binBytes);
        setBinOutput(binBase64);

        // Save the encrypted .bin file to Downloads
        await saveEncryptedFile(binBase64);
      } else {
        const ciphertextWithTag = base64ToBytes(inputText);

        if (ciphertextWithTag.length < 16) {
          throw new Error('Invalid ciphertext: too short (missing authentication tag)');
        }

        const plaintext = gcmDecrypt(ciphertextWithTag, processedKey, processedNonce);
        const outputText = bytesToString(plaintext);
        setOutput(outputText);

        const tag = ciphertextWithTag.slice(ciphertextWithTag.length - 16);
        const tagBase64 = bytesToBase64(tag);
        const tagHex = bytesToHex(tag);
        setTagDisplay(
          `Extracted Tag:\nBase64: ${tagBase64}\nHex: ${tagHex}\n\n✓ Tag verified successfully`
        );
      }
    } catch (err: any) {
      Alert.alert('Error', err.message || 'Operation failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const clearAll = () => {
    setInputText('');
    setKey('');
    setNonce('');
    setOutput('');
    setTagDisplay('');
    setBinOutput('');
    setBinFilePath('');
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.title}>🔐 AES-256-GCM Encryption</Text>
        <Text style={styles.subtitle}>Save .bin files to Downloads folder</Text>

        {/* Mode Toggle */}
        <View style={styles.modeContainer}>
          <Text style={styles.modeLabel}>Mode:</Text>
          <View style={styles.modeToggle}>
            <TouchableOpacity
              style={[styles.modeButton, mode === 'encrypt' && styles.modeButtonActive]}
              onPress={() => setMode('encrypt')}
            >
              <Text
                style={[
                  styles.modeButtonText,
                  mode === 'encrypt' && styles.modeButtonTextActive,
                ]}
              >
                Encrypt
              </Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.modeButton, mode === 'decrypt' && styles.modeButtonActive]}
              onPress={() => setMode('decrypt')}
            >
              <Text
                style={[
                  styles.modeButtonText,
                  mode === 'decrypt' && styles.modeButtonTextActive,
                ]}
              >
                Decrypt
              </Text>
            </TouchableOpacity>
          </View>
        </View>

        {/* Import BIN Button */}
        <TouchableOpacity
          style={[styles.importButton]}
          onPress={handleImportBin}
          disabled={isProcessing}
        >
          <Text style={styles.buttonText}>📥 Import .bin File</Text>
        </TouchableOpacity>

        {/* Input Text */}
        <View style={styles.inputGroup}>
          <Text style={styles.label}>
            {mode === 'encrypt' ? 'Plain Text:' : 'Encrypted Text (Base64 with Tag):'}
          </Text>
          <TextInput
            style={styles.textArea}
            value={inputText}
            onChangeText={setInputText}
            placeholder={
              mode === 'encrypt'
                ? 'Enter text to encrypt...'
                : 'Paste encrypted text (includes 16-byte tag)...'
            }
            placeholderTextColor="#9ca3af"
            multiline
            numberOfLines={4}
            editable={!isProcessing}
          />
        </View>

        {/* Key Input */}
        <View style={styles.inputGroup}>
          <View style={styles.labelRow}>
            <Text style={styles.label}>256-bit Key (Base64, 32 bytes):</Text>
            <TouchableOpacity 
              style={styles.smallButton} 
              onPress={generateRandomKey}
              disabled={isProcessing}
            >
              <Text style={styles.smallButtonText}>Generate</Text>
            </TouchableOpacity>
          </View>
          <TextInput
            style={styles.input}
            value={key}
            onChangeText={setKey}
            placeholder="e.g., AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
            placeholderTextColor="#9ca3af"
            editable={!isProcessing}
          />
          <Text style={[styles.hint, validateKey(key) ? styles.validHint : styles.invalidHint]}>
            {key ? `${Math.ceil((key.length * 3) / 4)} bytes - ${validateKey(key) ? '✓ Valid' : '✗ Invalid (needs 32 bytes)'}` : 'Enter 32-byte base64 key'}
          </Text>
        </View>

        {/* Nonce Input */}
        <View style={styles.inputGroup}>
          <View style={styles.labelRow}>
            <Text style={styles.label}>Nonce/IV (Base64, 12 bytes):</Text>
            <TouchableOpacity 
              style={styles.smallButton} 
              onPress={generateRandomNonce}
              disabled={isProcessing}
            >
              <Text style={styles.smallButtonText}>Generate</Text>
            </TouchableOpacity>
          </View>
          <TextInput
            style={styles.input}
            value={nonce}
            onChangeText={setNonce}
            placeholder="e.g., AQIDBAUGBwgJCgsM"
            placeholderTextColor="#9ca3af"
            editable={!isProcessing}
          />
          <Text style={[styles.hint, validateNonce(nonce) ? styles.validHint : styles.invalidHint]}>
            {nonce ? `${Math.ceil((nonce.length * 3) / 4)} bytes - ${validateNonce(nonce) ? '✓ Valid' : '✗ Invalid (needs 12 bytes)'}` : 'Enter 12-byte base64 nonce'}
          </Text>
        </View>

        {/* Action Buttons */}
        <View style={styles.buttonRow}>
          <TouchableOpacity 
            style={[styles.processButton, isProcessing && styles.disabledButton]} 
            onPress={handleProcess}
            disabled={isProcessing}
          >
            <Text style={styles.buttonText}>
              {isProcessing ? '⏳ Processing...' : mode === 'encrypt' ? '🔒 Encrypt & Save' : '🔓 Decrypt'}
            </Text>
          </TouchableOpacity>
          <TouchableOpacity 
            style={[styles.clearButton]} 
            onPress={clearAll}
            disabled={isProcessing}
          >
            <Text style={styles.buttonText}>Clear All</Text>
          </TouchableOpacity>
        </View>

        {/* Output */}
        {output ? (
          <View style={styles.outputContainer}>
            <Text style={styles.outputLabel}>
              {mode === 'encrypt' ? 'Encrypted Output (Base64):' : 'Decrypted Output:'}
            </Text>
            <View style={styles.outputBox}>
              <Text selectable style={styles.outputText}>{output}</Text>
            </View>
          </View>
        ) : null}

        {/* BIN Output (when encrypting) */}
        {binOutput && mode === 'encrypt' ? (
          <View style={styles.outputContainer}>
            <Text style={styles.outputLabel}>
              Binary .bin Format Preview:
            </Text>
            <View style={styles.outputBox}>
              <Text selectable style={styles.outputText}>
                {binOutput.substring(0, 100)}...
              </Text>
            </View>
            {binFilePath ? (
              <Text style={styles.filePath}>
                📍 Saved to: {binFilePath}
              </Text>
            ) : null}
          </View>
        ) : null}

        {/* Tag Display */}
        {tagDisplay ? (
          <View style={styles.tagContainer}>
            <Text style={styles.tagLabel}>🏷️ Authentication Tag (16 bytes):</Text>
            <View style={styles.tagBox}>
              <Text selectable style={styles.tagText}>{tagDisplay}</Text>
            </View>
          </View>
        ) : null}

        {/* Info Section */}
        <View style={styles.infoContainer}>
          <Text style={styles.infoTitle}>📋 About This Tool</Text>
          <Text style={styles.infoText}>
            • Encrypted .bin files are saved to <Text style={styles.infoBold}>Downloads folder</Text> (Android) or Documents (iOS)
          </Text>
          <Text style={styles.infoText}>
            • File format: [12-byte nonce][ciphertext][16-byte tag]
          </Text>
          <Text style={styles.infoText}>
            • Compatible with .NET AesGcmHelper & Python AESGCM
          </Text>
          <Text style={styles.infoText}>
            • Never reuse the same key + nonce combination!
          </Text>
        </View>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8fafc',
  },
  content: {
    padding: 20,
    paddingBottom: 40,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#1e293b',
    textAlign: 'center',
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 14,
    color: '#64748b',
    textAlign: 'center',
    marginBottom: 24,
  },
  modeContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 24,
    gap: 16,
  },
  modeLabel: {
    fontSize: 16,
    fontWeight: '600',
    color: '#334155',
  },
  modeToggle: {
    flexDirection: 'row',
    backgroundColor: '#e2e8f0',
    borderRadius: 8,
    padding: 4,
  },
  modeButton: {
    paddingHorizontal: 20,
    paddingVertical: 8,
    borderRadius: 6,
  },
  modeButtonActive: {
    backgroundColor: '#3b82f6',
  },
  modeButtonText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#64748b',
  },
  modeButtonTextActive: {
    color: '#ffffff',
  },
  inputGroup: {
    marginBottom: 16,
  },
  label: {
    fontSize: 14,
    fontWeight: '600',
    color: '#334155',
    marginBottom: 6,
  },
  labelRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 6,
  },
  smallButton: {
    backgroundColor: '#10b981',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 6,
  },
  smallButtonText: {
    fontSize: 12,
    fontWeight: '600',
    color: '#ffffff',
  },
  textArea: {
    borderWidth: 1,
    borderColor: '#cbd5e1',
    borderRadius: 8,
    padding: 12,
    fontSize: 14,
    color: '#1e293b',
    backgroundColor: '#ffffff',
    minHeight: 100,
    textAlignVertical: 'top',
  },
  input: {
    borderWidth: 1,
    borderColor: '#cbd5e1',
    borderRadius: 8,
    padding: 12,
    fontSize: 14,
    color: '#1e293b',
    backgroundColor: '#ffffff',
  },
  hint: {
    fontSize: 12,
    marginTop: 4,
  },
  validHint: {
    color: '#059669',
  },
  invalidHint: {
    color: '#dc2626',
  },
  buttonRow: {
    flexDirection: 'row',
    gap: 12,
    marginBottom: 20,
  },
  importButton: {
    backgroundColor: '#10b981',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
    marginBottom: 20,
  },
  processButton: {
    flex: 1,
    backgroundColor: '#3b82f6',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
  },
  clearButton: {
    backgroundColor: '#6b7280',
    paddingVertical: 14,
    paddingHorizontal: 20,
    borderRadius: 8,
    alignItems: 'center',
  },
  buttonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#ffffff',
  },
  disabledButton: {
    opacity: 0.6,
  },
  outputContainer: {
    backgroundColor: '#f1f5f9',
    borderWidth: 1,
    borderColor: '#cbd5e1',
    borderRadius: 8,
    padding: 16,
    marginBottom: 16,
  },
  outputLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: '#334155',
    marginBottom: 8,
  },
  outputBox: {
    backgroundColor: '#ffffff',
    padding: 12,
    borderRadius: 6,
    borderWidth: 1,
    borderColor: '#e2e8f0',
  },
  outputText: {
    fontSize: 12,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    color: '#1e293b',
  },
  filePath: {
    fontSize: 11,
    color: '#64748b',
    marginTop: 8,
    fontStyle: 'italic',
    backgroundColor: '#f8fafc',
    padding: 8,
    borderRadius: 4,
  },
  tagContainer: {
    backgroundColor: '#d1fae5',
    borderWidth: 1,
    borderColor: '#86efac',
    borderRadius: 8,
    padding: 16,
    marginBottom: 16,
  },
  tagLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: '#065f46',
    marginBottom: 8,
  },
  tagBox: {
    backgroundColor: '#ffffff',
    padding: 12,
    borderRadius: 6,
    borderWidth: 1,
    borderColor: '#86efac',
  },
  tagText: {
    fontSize: 12,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    color: '#047857',
  },
  infoContainer: {
    backgroundColor: '#e0f2fe',
    borderWidth: 1,
    borderColor: '#bae6fd',
    borderRadius: 8,
    padding: 16,
    marginTop: 20,
  },
  infoTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#0369a1',
    marginBottom: 8,
  },
  infoText: {
    fontSize: 13,
    color: '#0c4a6e',
    lineHeight: 20,
    marginBottom: 4,
  },
  infoBold: {
    fontWeight: '600',
  },
});

export default AesGcmScreen;