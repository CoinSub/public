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

export const toBase64Url = (buffer: string | Buffer): string => {
  return Buffer.from(buffer)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
};

export const toHex = (buffer: ArrayBuffer): string => {
  const view = new Uint8Array(buffer);
  let hexString = "";
  for (const byte of view) {
    const hexByte = byte.toString(16);
    hexString += hexByte.padStart(2, "0");
  }
  return hexString.toLowerCase();
};

async function sha256(data: Uint8Array): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", data);
}

async function exportPublicKeyPem(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("spki", key);
  const base64 = Buffer.from(exported).toString("base64");
  return `-----BEGIN PUBLIC KEY-----\n${base64}\n-----END PUBLIC KEY-----\n`;
}

function minimizeBigInt(value: Uint8Array): Uint8Array {
  if (value.length === 0) {
    return value;
  }
  const minValue = [0, ...value];
  for (let i = 0; i < minValue.length; ++i) {
    if (minValue[i] === 0) {
      continue;
    }
    if (minValue[i] > 0x7f) {
      return new Uint8Array(minValue.slice(i - 1));
    }
    return new Uint8Array(minValue.slice(i));
  }
  return new Uint8Array([0]);
}
function rawSignatureToAns1(rawSignature: Uint8Array): Uint8Array {
  if (rawSignature.length !== 64) {
    console.log(rawSignature.length);
    return new Uint8Array([0]);
  }
  const r = rawSignature.slice(0, 32);
  const s = rawSignature.slice(32);

  const minR = minimizeBigInt(r);
  const minS = minimizeBigInt(s);

  return new Uint8Array([
    0x30,
    minR.length + minS.length + 4,
    0x02,
    minR.length,
    ...minR,
    0x02,
    minS.length,
    ...minS,
  ]);
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
    signature: string;
  };
}> {
  // Validate credId
  if (!credId) {
    throw new Error("credId is required for signing");
  }

  // Create client data
  const clientData = {
    type: "key.get",
    challenge: options.challenge,
  };

  // Stringify client data
  const clientDataJson = JSON.stringify(clientData);

  // Sign the client data directly
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    keyPair.privateKey,
    new TextEncoder().encode(clientDataJson)
  );

  // Convert signature to ASN.1 DER format
  const signatureHex = rawSignatureToAns1(new Uint8Array(signature));

  return {
    credentialKind: "Key",
    credentialInfo: {
      credId,
      clientData: toBase64Url(Buffer.from(clientDataJson)),
      signature: toBase64Url(Buffer.from(signatureHex)),
    },
  };
}
