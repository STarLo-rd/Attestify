import { Attestation } from "../src/attestation";
import { Attest } from "../src/utils";
import * as ecc from "tiny-secp256k1";
import { BIP32Factory } from "bip32";
const bip32 = BIP32Factory(ecc);

// Mock data for testing
const mockCommitterXpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
const mockCommitteeXpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
const mockPayload = JSON.stringify({ uri: "https://pdfobject.com/pdf/sample.pdf" });

describe("Attestation Test Script", () => {
    describe("Attestation Creation", () => {
        it("should generate a unique attestation ID if none is provided", () => {
            const attestation = new Attestation(
                "",
                mockCommitterXpub,
                mockCommitteeXpub,
                "",
                mockPayload,
                "",
                "",
                "",
                Attest.INITIATED
            );
            expect(attestation.attestationId).toBeDefined();
            expect(attestation.attestationId).not.toBe("");
            expect(typeof attestation.attestationId).toBe("string");
        });

        it("should use provided attestation ID if one is given", () => {
            const customId = "custom-id-123";
            const attestation = new Attestation(
                customId,
                mockCommitterXpub,
                mockCommitteeXpub,
                "",
                mockPayload,
                "",
                "",
                "",
                Attest.INITIATED
            );
            expect(attestation.attestationId).toBe(customId);
        });
    });
});
