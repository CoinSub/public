import { webcrypto as crypto } from "crypto";
import { getOrCreateKeyPair } from "./keyManager";
import { signChallenge, UserActionChallengeSignOptions } from "./signUAC";
import { PublicKeyCredentialCreationOptions, sign } from "./signCreate";

// Make crypto available globally
(global as any).crypto = crypto;

async function main() {
  // Get or create key pair
  const keyPair = await getOrCreateKeyPair();

  try {
    const creationOptions: PublicKeyCredentialCreationOptions = {
      attestation: "direct",
      challenge: "Y2gtMzE5cjYtNml0NHEtOWpyOWxqbWE3aXAycmtwaA",
      pubKeyCredParams: [
        {
          alg: -257,
          type: "public-key",
        },
        {
          alg: -7,
          type: "public-key",
        },
      ],
      rp: {
        id: "dfns.ninja",
        name: "Dfns",
      },
      user: {
        displayName: "sasa100@qa.team (or-4fp3b-4ocka-8idbmfl1fkbv8tq5)",
        id: "us-7o8e7-k9tem-8tsakblm8niou1pe",
        name: "sasa100@qa.team",
      },
    };

    const resultCreate = await sign(creationOptions, keyPair);
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

    // const requestOptions: UserActionChallengeSignOptions = {
    //   allowCredentials: {
    //     key: [
    //       {
    //         id: "7o5o51HQeF_9Xk_4P41Rth01sTRH0Kugy8kVDoQhG3g",
    //         type: "public-key",
    //       },
    //     ],
    //     webauthn: [
    //       {
    //         id: "RvgAvRk9jBVdw_bZGKHFv3y1eQU",
    //         type: "public-key",
    //       },
    //     ],
    //   },
    //   attestation: "direct",
    //   challenge: "Y2gtNGtmc2ItaDliaWstOHYzb2tsMnVsM3Ezc3RlcA",
    //   challengeIdentifier:
    //     "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJhdXRoLmRmbnMubmluamEiLCJhdWQiOiJkZm5zOmF1dGg6dXNlciIsInN1YiI6Im9yLTRmcDNiLTRvY2thLThpZGJtZmwxZmtidjh0cTUiLCJqdGkiOiJ1ai0ycTh2by12cG0wNy05NWViOG8yZzkwNHJqbnNiIiwiaHR0cHM6Ly9jdXN0b20vdXNlcm5hbWUiOiJzYXNhMTAwQHFhLnRlYW0iLCJodHRwczovL2N1c3RvbS9hcHBfbWV0YWRhdGEiOnsidXNlcklkIjoidXMtN284ZTctazl0ZW0tOHRzYWtibG04bmlvdTFwZSIsIm9yZ0lkIjoib3ItNGZwM2ItNG9ja2EtOGlkYm1mbDFma2J2OHRxNSIsInRva2VuS2luZCI6IlRlbXAiLCJjaGFsbGVuZ2UiOiJZMmd0Tkd0bWMySXRhRGxpYVdzdE9IWXpiMnRzTW5Wc00zRXpjM1JsY0EiLCJjaGFsbGVuZ2VJbmZvIjp7InBheWxvYWQiOiJ7XCJhbW91bnRcIjpcIjEwMFwiLFwia2luZFwiOlwiTmF0aXZlXCIsXCJ0b1wiOlwiMHhCNjY3ZGMxMDMzMmNiQzFBYkJkNmM2ODE1YjY0NzRiMjE2RGNBZDRlXCJ9IiwibWV0aG9kIjoiUE9TVCIsInBhdGgiOiIvd2FsbGV0cy93YS00MWJlZy1zc3E4bi04azk4YTIxcTZpczdzMmRlL3RyYW5zZmVycyIsInNlcnZlciI6ImFwaS5kZm5zLm5pbmphIiwic3VtbWFyeSI6IlRyYW5zZmVyIE5hdGl2ZSBhc3NldCB0byByZWNpcGllbnQgMHhCNjY3ZGMxMDMzMmNiQzFBYkJkNmM2ODE1YjY0NzRiMjE2RGNBZDRlLiIsIm5vbmNlIjoibm8tamhkY2QtODYwNTgtdHQ5NTRyNG1pajJwbmk1In19LCJpYXQiOjE3NDk1NjQ0MzQsImV4cCI6MTc0OTU2NTMzNH0.t3xhp8OcbsvrNwwFWNN6katGqeuzC-vQrxks5Cic_ncR4vpypJWaJIiEadYa2ElyHRTW1GKHdkQQrVZXeD5pBQ",
    //   externalAuthenticationUrl: "",
    //   rp: {
    //     id: "dfns.ninja",
    //     name: "Dfns",
    //   },
    //   supportedCredentialKinds: [
    //     {
    //       factor: "either",
    //       kind: "Fido2",
    //       requiresSecondFactor: false,
    //     },
    //     {
    //       factor: "either",
    //       kind: "Key",
    //       requiresSecondFactor: false,
    //     },
    //   ],
    //   userVerification: "required",
    // };

    // const resultSign = await signChallenge(
    //   requestOptions,
    //   keyPair,
    //   "credential-id"
    // );
    // console.log("Credential Kind:", resultSign.credentialKind);
    // console.log(
    //   "Credential Info:",
    //   JSON.stringify(
    //     {
    //       credId: resultSign.credentialInfo.credId,
    //       clientData: resultSign.credentialInfo.clientData,
    //       attestationData: resultSign.credentialInfo.attestationData,
    //     },
    //     null,
    //     2
    //   )
    // );
  } catch (error) {
    console.error("Error:", error);
  }
}

main();
