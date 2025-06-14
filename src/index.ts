import { webcrypto as crypto } from "crypto";
import { getOrCreateKeyPair } from "./keyManager";
import {
  signChallenge,
  UserActionChallengeSignOptions,
} from "./signUserActionChallenge";
import {
  PublicKeyCredentialCreationOptions,
  create,
} from "./signCreateCredChallenge";
import * as fs from "fs/promises";

// Make crypto available globally
(global as any).crypto = crypto;

function isCreateChallenge(
  challenge: any
): challenge is PublicKeyCredentialCreationOptions {
  return (
    challenge.pubKeyCredParams !== undefined &&
    challenge.user !== undefined &&
    challenge.rp !== undefined
  );
}

function isActionChallenge(
  challenge: any
): challenge is UserActionChallengeSignOptions {
  return (
    challenge.allowCredentials !== undefined &&
    challenge.challengeIdentifier !== undefined &&
    challenge.supportedCredentialKinds !== undefined
  );
}

async function main() {
  try {
    // Read challenge configuration
    console.log("Reading challenge configuration...");
    const challengeConfig = JSON.parse(
      await fs.readFile("challenge.json", "utf-8")
    );

    // Get or create key pair
    const keyPair = await getOrCreateKeyPair();

    // Determine operation type
    console.log("Determining operation type...");
    if (isCreateChallenge(challengeConfig)) {
      console.log("Detected CREATE CREDENTIAL challenge");
      const resultCreate = await create(challengeConfig, keyPair);
      console.log("Credential created successfully");
      console.log("Credential Kind:", resultCreate.credentialKind);
      console.log(
        "Credential Info:",
        JSON.stringify(
          {
            credId: resultCreate.credentialInfo.credId,
            clientData: resultCreate.credentialInfo.clientData,
            attestationData: resultCreate.credentialInfo.attestationData,
          },
          null,
          2
        )
      );
    } else if (isActionChallenge(challengeConfig)) {
      console.log("Detected USER ACTION challenge");
      // For action operations, we need the credential ID
      if (!process.argv[2]) {
        console.error("Please provide a credential ID for signing");
        process.exit(1);
      }

      console.log("Using credential ID:", process.argv[2]);
      const resultSign = await signChallenge(
        challengeConfig,
        keyPair,
        process.argv[2]
      );
      console.log("Challenge signed successfully");
      console.log("Credential Kind:", resultSign.credentialKind);
      console.log(
        "Credential Info:",
        JSON.stringify(
          {
            credId: resultSign.credentialInfo.credId,
            clientData: resultSign.credentialInfo.clientData,
            signature: resultSign.credentialInfo.signature,
          },
          null,
          2
        )
      );
    } else {
      console.error(
        "Invalid challenge format. The challenge must be either a create or action challenge."
      );
      process.exit(1);
    }
  } catch (error) {
    console.error("Error:", error);
  }
}

main();
