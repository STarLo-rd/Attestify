import { Attestation } from "../src/attestation";
import { Attest } from "../src/utils";
import * as ecc from "tiny-secp256k1";
import { BIP32Factory } from "bip32";
import { generateMnemonic, mnemonicToSeedSync } from 'bip39';
const bip32 = BIP32Factory(ecc);
import bitcoin from 'bitcoinjs-lib';
import { ERROR_MESSAGES } from "../src/constants";

// Mock data for testing
const committerMnemonic = "empty expose treat boss purchase someone dawn later fat icon exile broccoli";
const committeeMnemonic = "universe pulse thank truth rescue business elite seed grab black repair trim";

const committerSeed = mnemonicToSeedSync(committerMnemonic);
const committeeSeed = mnemonicToSeedSync(committeeMnemonic);

const committerNode = bip32.fromSeed(committerSeed);
const committeeNode = bip32.fromSeed(committeeSeed);

const committerPathNode = committerNode.derivePath("m/44'/60'/0'/0");
const committeePathNode = committeeNode.derivePath("m/44'/60'/0'/0");

const committerXpub = committerPathNode.neutered().toBase58();
const committeeXpub = committeePathNode.neutered().toBase58();

console.log(committerXpub)
console.log(committeeXpub)

const mockPayload = JSON.stringify({ uri: "https://pdfobject.com/pdf/sample.pdf" });

describe("Attestation Test Script", () => {
    // describe("Intitalise Attestation", () => {
    //     it("should generate a unique attestation ID if none is provided", () => {
    //         const attestation = new Attestation(
    //             "",
    //             committerXpub,
    //             committeeXpub,
    //             "m/44'/60'/0'/0",
    //             mockPayload,
    //             "",
    //             "",
    //             "",
    //             Attest.INITIATED
    //         );
    //         expect(attestation.attestationId).toBeDefined();
    //         expect(attestation.attestationId).not.toBe("");
    //         expect(typeof attestation.attestationId).toBe("string");
    //     });
    //     it("should use provided attestation ID if one is given", () => {
    //         const customId = "custom-id-123";
    //         const attestation = new Attestation(
    //             customId,
    //             committerXpub,
    //             committeeXpub,
    //             "m/44'/60'/0'/0",
    //             mockPayload,
    //             "",
    //             "",
    //             "",
    //             Attest.INITIATED
    //         );
    //         expect(attestation.attestationId).toBe(customId);
    //     });
    // });
    // describe("Intitiate Attestation", () => {
    //     it("should initiate an attestation", () => {
    //         const attestation = new Attestation(
    //             "",
    //             committerXpub,
    //             committeeXpub,
    //             "m/44'/60'/0'/0",
    //             mockPayload,
    //             "",
    //             "",
    //             "",
    //             Attest.INITIATED
    //         );
    //         expect(attestation.attestationId).toBeDefined();
    //         expect(attestation.attestationId).not.toBe("");
    //         expect(typeof attestation.attestationId).toBe("string");
    //         attestation.initiateAttestation();
    //         expect(attestation.commitmentState).toBe(Attest.INITIATED);
    //     });
    //     it("should throw error when attestation is already past INITIATED", () => {
    //         const attestation = new Attestation(
    //             "",
    //             committerXpub,
    //             committeeXpub,
    //             "m/44'/60'/0'/0",
    //             mockPayload,
    //             "",
    //             "",
    //             "",
    //             Attest.DISCHARGED
    //         );
    //         expect(attestation.attestationId).toBeDefined();
    //         expect(attestation.attestationId).not.toBe("");
    //         expect(typeof attestation.attestationId).toBe("string");
    //         expect(() => attestation.initiateAttestation()).toThrow(
    //             ERROR_MESSAGES.ALREADY_INITIATED
    //         );
    //     });
    // });
    describe("Acknowledge Attestation", () => {
        // it("should acknowledge an attestation", () => {
        //     const attestation = new Attestation(
        //         "uuid",
        //         committerXpub,
        //         committeeXpub,
        //         "m/44'/60'/0'/0",
        //         mockPayload,
        //         "",
        //         "",
        //         "",
        //         Attest.INITIATED
        //     );
        //     let committeeSignature = attestation.sign(committeeMnemonic);
        //     attestation.setCommitteeSignature(committeeSignature);
        //     attestation.acknowledgeAttestation()
        //     expect(attestation.commitmentState).toBe(Attest.ACKNOWLEDGED);
        // });
        // it("should not acknowledge an attestation with incorrect signature", () => {
        //     const attestation = new Attestation(
        //         "",
        //         committerXpub,
        //         committeeXpub,
        //         "m/44'/60'/0'/0",
        //         mockPayload,
        //         "",
        //         "",
        //         "",
        //         Attest.INITIATED
        //     );
        //     let committeeSignature = attestation.sign("committeeMnemonic");
        //     attestation.setCommitteeSignature(committeeSignature);
        //     attestation.acknowledgeAttestation()
        //     expect(attestation.commitmentState).toBe(Attest.ACKNOWLEDGED);
        // });
    });
    describe("Accept Attestation", () => {
        it("should accept an attestation", () => {
            const attestation = new Attestation(
                "uuid",
                committerXpub,
                committeeXpub,
                "m/44'/60'/0'/0",
                mockPayload,
                "",
                "",
                "",
                Attest.ACKNOWLEDGED
            );
            let committeeSignature = attestation.sign(committeeMnemonic);
            attestation.setCommitteeSignature(committeeSignature);
            let committerSignature = attestation.sign(committerMnemonic);
            attestation.setCommitterSignature(committerSignature);
            attestation.acceptAttestation();
            expect(attestation.commitmentState).toBe(Attest.EFFECTIVE);
        });
        // it("should not accept an attestation with incorrect signature", () => {
        //     const attestation = new Attestation(
        //         "",
        //         committerXpub,
        //         committeeXpub,
        //         "m/44'/60'/0'/0",
        //         mockPayload,
        //         "",
        //         "",
        //         "",
        //         Attest.ACKNOWLEDGED
        //     );
        //     let committeeSignature = attestation.sign(committeeMnemonic);
        //     attestation.setCommitteeSignature(committeeSignature);
        //     let committerSignature = attestation.sign(committeeMnemonic);
        //     attestation.setCommitterSignature(committerSignature);
        //     attestation.acceptAttestation()
        //     expect(attestation.commitmentState).toBe(Attest.EFFECTIVE);
        // });
    });
});
