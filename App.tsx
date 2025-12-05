/**
 * AES-256-GCM decrypt using react-native-aes-gcm-crypto
 * cipherBase64 includes the TAG automatically → no need to input tag
 */

import React, { useEffect, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  StatusBar,
  useColorScheme,
} from "react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";

import AesGcmCrypto from "react-native-aes-gcm-crypto";

export default function App() {
  const isDark = useColorScheme() === "dark";
  return (
    <SafeAreaProvider>
      <StatusBar barStyle={isDark ? "light-content" : "dark-content"} />
      <Main />
    </SafeAreaProvider>
  );
}

function Main() {
  const [result, setResult] = useState("Decrypting...");
  const [error, setError] = useState("");

  // Base64 → Uint8Array
  const base64ToBytes = (b64: string) => {
    const raw = atob(b64);
    const arr = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    return arr;
  };

  // Bytes → hex string
  const bytesToHex = (bytes: Uint8Array) => {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  };

  useEffect(() => {
    const decryptNow = async () => {
      try {
        // --------------------------
        // Your Base64 Inputs
        // --------------------------
        const keyBase64 = "fg0iDJRvOfbSn7tg";     // base64 key
        const ivBase64 = "MTMxMzQ4YzA5ODdjN2VlY2U2MGZjMGJj"; // base64 IV
        const cipherBase64 = "LzpSalRKfL47H5rUhqvA"; // base64 (cipher + tag)

        // Convert Base64 → bytes
        const cipherBytes = base64ToBytes(cipherBase64);

        // --------------------------
        // AUTO-SPLIT TAG
        // Last 16 bytes = GCM auth tag
        // --------------------------
        const tagBytes = cipherBytes.slice(cipherBytes.length - 16);
        const encryptedBytes = cipherBytes.slice(0, cipherBytes.length - 16);

        // Convert required items
        const encryptedBase64 = btoa(String.fromCharCode(...encryptedBytes));
        const tagHex = bytesToHex(tagBytes);
        const ivHex = bytesToHex(base64ToBytes(ivBase64));

        // Decrypt
        const plaintext = await AesGcmCrypto.decrypt(
          encryptedBase64,
          keyBase64,
          ivHex,
          tagHex,
          false   // return UTF-8 string
        );

        setResult(plaintext);
      } catch (err: any) {
        setError(err?.message ?? String(err));
      }
    };

    decryptNow();
  }, []);

  return (
    <View style={styles.container}>
      <Text style={styles.title}>AES-256-GCM Decryption</Text>
      {error ? (
        <Text style={styles.error}>{error}</Text>
      ) : (
        <Text style={styles.text}>Decrypted: {result}</Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#121212",
    alignItems: "center",
    justifyContent: "center",
  },
  title: {
    fontSize: 20,
    fontWeight: "700",
    color: "#ffffff",
    marginBottom: 10,
  },
  text: {
    fontSize: 16,
    color: "#dddddd",
  },
  error: {
    fontSize: 16,
    color: "#ff6b6b",
  },
});
