import { webcrypto as crypto } from "crypto";
import { getOrCreateKeyPair } from "./keyManager";
import { signChallenge, UserActionChallengeSignOptions } from "./signUAC";
import { PublicKeyCredentialCreationOptions, sign } from "./signCreate";

// Make crypto available globally
(global as any).crypto = crypto;

async function main() {
  // Get or create key pair
  const keyPair = await getOrCreateKeyPair();

  //Uncomment the option you want to use

  try {
    //SIGN CREATE CREDENTIAL
    // const creationOptions: PublicKeyCredentialCreationOptions = {
    //   attestation: "direct",
    //   challenge: "Y2gtMzE5cjYtNml0NHEtOWpyOWxqbWE3aXAycmtwaA",
    //   pubKeyCredParams: [
    //     {
    //       alg: -257,
    //       type: "public-key",
    //     },
    //     {
    //       alg: -7,
    //       type: "public-key",
    //     },
    //   ],
    //   rp: {
    //     id: "dfns.ninja",
    //     name: "Dfns",
    //   },
    //   user: {
    //     displayName: "sasa100@qa.team (or-4fp3b-4ocka-8idbmfl1fkbv8tq5)",
    //     id: "us-7o8e7-k9tem-8tsakblm8niou1pe",
    //     name: "sasa100@qa.team",
    //   },
    // };

    // const resultCreate = await sign(creationOptions, keyPair);
    // console.log("Credential Kind:", resultCreate.credentialKind);
    // console.log(
    //   "Credential Info:",
    //   JSON.stringify(
    //     {
    //       credId: resultCreate.credentialInfo.credId,
    //       clientData: resultCreate.credentialInfo.clientData,
    //       attestationData: resultCreate.credentialInfo.attestationData,
    //     },
    //     null,
    //     2
    //   )
    // );

    //SIGN USER ACTION CHALLENGE
    const requestOptions: UserActionChallengeSignOptions = {
      allowCredentials: {
        key: [
          {
            id: "7o5o51HQeF_9Xk_4P41Rth01sTRH0Kugy8kVDoQhG3g",
            type: "public-key",
          },
        ],
        webauthn: [
          {
            id: "RvgAvRk9jBVdw_bZGKHFv3y1eQU",
            type: "public-key",
          },
        ],
      },
      attestation: "direct",
      challenge: "Y2gtNHFyODEtMWdxczYtOWZjYXVtdW9nbDIybHE1dA",
      challengeIdentifier:
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJhdXRoLmRmbnMubmluamEiLCJhdWQiOiJkZm5zOmF1dGg6dXNlciIsInN1YiI6Im9yLTRmcDNiLTRvY2thLThpZGJtZmwxZmtidjh0cTUiLCJqdGkiOiJ1ai1mcDZhcC1ubG9hOS1hNzh2aTJzOWhvMnIxMnEiLCJodHRwczovL2N1c3RvbS91c2VybmFtZSI6InNhc2ExMDBAcWEudGVhbSIsImh0dHBzOi8vY3VzdG9tL2FwcF9tZXRhZGF0YSI6eyJ1c2VySWQiOiJ1cy03bzhlNy1rOXRlbS04dHNha2JsbThuaW91MXBlIiwib3JnSWQiOiJvci00ZnAzYi00b2NrYS04aWRibWZsMWZrYnY4dHE1IiwidG9rZW5LaW5kIjoiVGVtcCIsImNoYWxsZW5nZSI6IlkyZ3ROSEZ5T0RFdE1XZHhjell0T1daallYVnRkVzluYkRJeWJIRTFkQSIsImNoYWxsZW5nZUluZm8iOnsicGF5bG9hZCI6IntcImFtb3VudFwiOlwiMTAwXCIsXCJraW5kXCI6XCJOYXRpdmVcIixcInRvXCI6XCIweEI2NjdkYzEwMzMyY2JDMUFiQmQ2YzY4MTViNjQ3NGIyMTZEY0FkNGVcIn0iLCJtZXRob2QiOiJQT1NUIiwicGF0aCI6Ii93YWxsZXRzL3dhLTQxYmVnLXNzcThuLThrOThhMjFxNmlzN3MyZGUvdHJhbnNmZXJzIiwic2VydmVyIjoiYXBpLmRmbnMubmluamEiLCJzdW1tYXJ5IjoiVHJhbnNmZXIgTmF0aXZlIGFzc2V0IHRvIHJlY2lwaWVudCAweEI2NjdkYzEwMzMyY2JDMUFiQmQ2YzY4MTViNjQ3NGIyMTZEY0FkNGUuIiwibm9uY2UiOiJuby03YTVqdi1sM3I4dC05aTRycnM2aDJlM3NrMm5zIn19LCJpYXQiOjE3NDk2NDQ2ODUsImV4cCI6MTc0OTY0NTU4NX0.zWT3TMjM-vxIZE7mn5DW-Y0FsDh-djxFDwzYZHzyBnH-rV6SgqucmMqbjewSdeGt4Gncxkc8jCY1VbUBOlBuCw",
      externalAuthenticationUrl: "",
      rp: {
        id: "dfns.ninja",
        name: "Dfns",
      },
      supportedCredentialKinds: [
        {
          factor: "either",
          kind: "Fido2",
          requiresSecondFactor: false,
        },
        {
          factor: "either",
          kind: "Key",
          requiresSecondFactor: false,
        },
      ],
      userVerification: "required",
    };

    const resultSign = await signChallenge(
      requestOptions,
      keyPair,
      "7o5o51HQeF_9Xk_4P41Rth01sTRH0Kugy8kVDoQhG3g"
    );
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
  } catch (error) {
    console.error("Error:", error);
  }
}

main();
