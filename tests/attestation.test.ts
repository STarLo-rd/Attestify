import { Attestation } from "../src/attestation";
import { Attest } from "../src/utils";
import * as ecc from "tiny-secp256k1";
import { BIP32Factory } from "bip32";
import { mnemonicToSeedSync } from 'bip39';
const bip32 = BIP32Factory(ecc);

describe("Attestation Lifecycle Test Suite", () => {
  // Test setup and constants
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

  const mockPayload = JSON.stringify({ uri: "https://pdfobject.com/pdf/sample.pdf" });

  let attestation: Attestation;

  beforeEach(() => {
    // Create fresh attestation instance before each test
    attestation = new Attestation(
      committerXpub,
      committeeXpub,
      "m/44'/60'/0'/0",
      mockPayload,
      "",
      "",
      "",
      Attest.INITIATED
    );
  });

  describe("Complete Attestation Lifecycle", () => {
    it("should initialize attestation in the INITIATED state", () => {
      // Check if the attestation starts in the INITIATED state
      expect(attestation.commitmentState).toBe(Attest.INITIATED);
    });

    it("should allow committee to acknowledge attestation", () => {
      // Step 1: Committee acknowledges attestation
      const committeeSignature = attestation.sign(committeeMnemonic);
      attestation.setCommitteeSignature(committeeSignature);
      attestation.acknowledgeAttestation();

      // Verify state and signature
      expect(attestation.commitmentState).toBe(Attest.ACKNOWLEDGED);
      expect(attestation.getCommitteeSignature()).toBe(committeeSignature);
    });

    it("should allow committer to accept attestation", () => {
      // Step 1: Committee acknowledges attestation
      const committeeSignature = attestation.sign(committeeMnemonic);
      attestation.setCommitteeSignature(committeeSignature);
      attestation.acknowledgeAttestation();

      // Step 2: Committer accepts attestation
      const committerSignature = attestation.sign(committerMnemonic);
      attestation.setCommitterSignature(committerSignature);
      attestation.acceptAttestation();

      // Verify state and signature
      expect(attestation.commitmentState).toBe(Attest.EFFECTIVE);
      expect(attestation.getCommitterSignature()).toBe(committerSignature);
    });

    it("should allow discharge of attestation", () => {
      // Step 1: Committee acknowledges attestation
      const committeeSignature = attestation.sign(committeeMnemonic);
      attestation.setCommitteeSignature(committeeSignature);
      attestation.acknowledgeAttestation();

      // Step 2: Committer accepts attestation
      const committerSignature = attestation.sign(committerMnemonic);
      attestation.setCommitterSignature(committerSignature);
      attestation.acceptAttestation();

      // Step 3: Discharge attestation
      const dischargeSignature = attestation.sign(committerMnemonic);
      attestation.setDischargeSignature(dischargeSignature);
      attestation.dischargeAttestation();

      // Verify state and signature
      expect(attestation.commitmentState).toBe(Attest.DISCHARGED);
      expect(attestation.getDischargeSignature()).toBe(dischargeSignature);
    });

    it("should fail to acknowledge without committee signature", () => {
      // Attempt to acknowledge without a committee signature
      expect(() => attestation.acknowledgeAttestation()).toThrow();
    });

    it("should fail to accept without committer signature", () => {
      // Step 1: Committee acknowledges attestation
      const committeeSignature = attestation.sign(committeeMnemonic);
      attestation.setCommitteeSignature(committeeSignature);
      attestation.acknowledgeAttestation();

      // Attempt to accept without a committer signature
      expect(() => attestation.acceptAttestation()).toThrow();
    });

    it("should fail to discharge without discharge signature", () => {
      // Step 1: Committee acknowledges attestation
      const committeeSignature = attestation.sign(committeeMnemonic);
      attestation.setCommitteeSignature(committeeSignature);
      attestation.acknowledgeAttestation();

      // Step 2: Committer accepts attestation
      const committerSignature = attestation.sign(committerMnemonic);
      attestation.setCommitterSignature(committerSignature);
      attestation.acceptAttestation();

      // Attempt to discharge without a discharge signature
      expect(() => attestation.dischargeAttestation()).toThrow();
    });

    it("should verify signatures at each stage", () => {
      // Committee signature verification
      const committeeSignature = attestation.sign(committeeMnemonic);
      attestation.setCommitteeSignature(committeeSignature);
      expect(attestation.getCommitteeSignature()).toBe(committeeSignature);

      // Committer signature verification
      const committerSignature = attestation.sign(committerMnemonic);
      attestation.setCommitterSignature(committerSignature);
      expect(attestation.getCommitterSignature()).toBe(committerSignature);

      // Discharge signature verification
      const dischargeSignature = attestation.sign(committerMnemonic);
      attestation.setDischargeSignature(dischargeSignature);
      expect(attestation.getDischargeSignature()).toBe(dischargeSignature);
    });

    it("should not allow out-of-order state transitions", () => {
      // Attempt to accept before acknowledging
      expect(() => attestation.acceptAttestation()).toThrow();

      // Attempt to discharge before attestation is effective
      expect(() => attestation.dischargeAttestation()).toThrow();

      // Get to ACKNOWLEDGED state
      const committeeSignature = attestation.sign(committeeMnemonic);
      attestation.setCommitteeSignature(committeeSignature);
      attestation.acknowledgeAttestation();

      // Attempt to initiate after already acknowledged
      expect(() => attestation.initiateAttestation()).toThrow();
    });

    it("should maintain correct derived keys throughout lifecycle", () => {
      const derivedCommitter = attestation.committer;
      const derivedCommittee = attestation.committee;

      // Complete full lifecycle
      const committeeSignature = attestation.sign(committeeMnemonic);
      attestation.setCommitteeSignature(committeeSignature);
      attestation.acknowledgeAttestation();

      const committerSignature = attestation.sign(committerMnemonic);
      attestation.setCommitterSignature(committerSignature);
      attestation.acceptAttestation();

      const dischargeSignature = attestation.sign(committerMnemonic);
      attestation.setDischargeSignature(dischargeSignature);
      attestation.dischargeAttestation();

      // Verify keys remained constant
      expect(attestation.committer).toBe(derivedCommitter);
      expect(attestation.committee).toBe(derivedCommittee);
    });
  });

  describe("Edge Case Handling", () => {
    it("should correctly handle empty or missing attestationId", () => {
      // Create attestation with missing attestationId
      const attestationWithoutId = new Attestation(
        committerXpub,
        committeeXpub,
        "m/44'/60'/0'/0",
        mockPayload,
        "",
        "",
        "",
        Attest.INITIATED
      );

      // Check if attestationId is generated
      expect(attestationWithoutId.attestationId).toBeDefined();
    });

    it("should throw error for invalid public key format", () => {
      // Test with invalid public key format
      const invalidXpub = "invalidXpub";
      expect(() => {
        new Attestation(
          invalidXpub,
          committeeXpub,
          "m/44'/60'/0'/0",
          mockPayload,
          "",
          "",
          "",
          Attest.INITIATED
        );
      }).toThrow();
    });

    // it("should handle incorrect derivation paths gracefully", () => {
    //   // Test with incorrect derivation path
    //   expect(() => {
    //     new Attestation(
    //       committerXpub,
    //       committeeXpub,
    //       "m/44'/60'/0'/0/invalid",
    //       mockPayload,
    //       "",
    //       "",
    //       "",
    //       Attest.INITIATED
    //     );
    //   }).toThrow();
    // });
  });
});
