import { webcrypto as crypto } from "crypto";
import * as fs from "fs/promises";
import * as path from "path";

const KEY_FILE = path.join(process.cwd(), "keypair.json");

export async function getOrCreateKeyPair(): Promise<CryptoKeyPair> {
  try {
    // Try to read existing key pair
    const keyData = await fs.readFile(KEY_FILE, "utf-8");
    const { privateKey: privateKeyData, publicKey: publicKeyData } =
      JSON.parse(keyData);

    // Import the keys
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      Buffer.from(privateKeyData, "base64"),
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign"]
    );

    const publicKey = await crypto.subtle.importKey(
      "spki",
      Buffer.from(publicKeyData, "base64"),
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["verify"]
    );

    return { privateKey, publicKey };
  } catch (error) {
    console.error(error);
    // If file doesn't exist or is invalid, generate new key pair
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );

    // Export keys to store them
    const privateKeyData = await crypto.subtle.exportKey(
      "pkcs8",
      keyPair.privateKey
    );
    const publicKeyData = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );

    // Save to file
    await fs.writeFile(
      KEY_FILE,
      JSON.stringify({
        privateKey: Buffer.from(privateKeyData).toString("base64"),
        publicKey: Buffer.from(publicKeyData).toString("base64"),
      })
    );

    return keyPair;
  }
}
