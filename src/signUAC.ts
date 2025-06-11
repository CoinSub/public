import { webcrypto as crypto } from "crypto";
import { Buffer } from "buffer";

export interface UserActionChallengeSignOptions {
  challenge: string;
  challengeIdentifier: string;
  rp: {
    id: string;
    name: string;
  };
  allowCredentials: {
    key?: Array<{
      id: string;
      type: string;
    }>;
    webauthn?: Array<{
      id: string;
      type: string;
    }>;
  };
  supportedCredentialKinds: Array<{
    kind: string;
    factor: string;
    requiresSecondFactor: boolean;
  }>;
  userVerification: string;
  attestation?: string;
  externalAuthenticationUrl?: string;
}

function toBase64Url(buffer: Buffer): string {
  return buffer.toString("base64url");
}

function toHex(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("hex");
}

async function sha256(data: Uint8Array): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", data);
}

async function exportPublicKeyPem(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("spki", key);
  const base64 = Buffer.from(exported).toString("base64");
  return `-----BEGIN PUBLIC KEY-----\n${base64}\n-----END PUBLIC KEY-----\n`;
}

function rawSignatureToAns1(signature: ArrayBuffer): string {
  const r = new Uint8Array(signature.slice(0, 32));
  const s = new Uint8Array(signature.slice(32));

  // Convert to ASN.1 DER format
  const rNeedsLeadingZero = r[0] & 0x80;
  const sNeedsLeadingZero = s[0] & 0x80;

  // Calculate lengths
  const rContentLen = rNeedsLeadingZero ? 33 : 32;
  const sContentLen = sNeedsLeadingZero ? 33 : 32;
  const rTotalLen = rContentLen + 2; // +2 for 0x02 and length byte
  const sTotalLen = sContentLen + 2; // +2 for 0x02 and length byte
  const totalLen = rTotalLen + sTotalLen + 2; // +2 for sequence header

  const der = new Uint8Array(totalLen);
  let offset = 0;

  // Sequence header
  der[offset++] = 0x30;
  der[offset++] = totalLen - 2;

  // R value
  der[offset++] = 0x02;
  der[offset++] = rContentLen;
  if (rNeedsLeadingZero) {
    der[offset++] = 0x00;
  }
  der.set(r, offset);
  offset += 32;

  // S value
  der[offset++] = 0x02;
  der[offset++] = sContentLen;
  if (sNeedsLeadingZero) {
    der[offset++] = 0x00;
  }
  der.set(s, offset);

  return toHex(der);
}

export async function signChallenge(
  options: UserActionChallengeSignOptions,
  keyPair: CryptoKeyPair,
  credId: string
): Promise<{
  credentialKind: string;
  credentialInfo: {
    credId: string;
    clientData: string;
    attestationData: string;
  };
}> {
  // Create client data with sorted keys
  const clientData = {
    challenge: options.challenge,
    type: "key.get",
  };

  // Stringify client data with specific format
  const clientDataJson = JSON.stringify(clientData);
  const clientDataBuffer = new TextEncoder().encode(clientDataJson);
  const clientDataHash = await sha256(clientDataBuffer);
  const clientDataHashHex = toHex(clientDataHash);

  // Create credential info fingerprint
  const publicKeyPem = await exportPublicKeyPem(keyPair.publicKey);
  const credentialInfoFingerprint = {
    clientDataHash: clientDataHashHex,
    publicKey: publicKeyPem,
  };

  // Stringify credential info fingerprint with specific format
  const fingerprintJson = JSON.stringify(credentialInfoFingerprint);
  const fingerprintBuffer = new TextEncoder().encode(fingerprintJson);

  // Sign the fingerprint
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    keyPair.privateKey,
    fingerprintBuffer
  );

  // Convert signature to ASN.1 DER format
  const signatureHex = rawSignatureToAns1(signature);

  // Create attestation data object
  const attestationData = {
    publicKey: publicKeyPem,
    signature: signatureHex,
  };

  return {
    credentialKind: "Key",
    credentialInfo: {
      credId,
      clientData: toBase64Url(Buffer.from(clientDataJson)),
      attestationData: toBase64Url(
        Buffer.from(JSON.stringify(attestationData))
      ),
    },
  };
}
