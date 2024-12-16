const bip39 = require('bip39');
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const { ec } = require('elliptic');
const crypto = require('crypto');

// Create BIP32 instance
const bip32 = BIP32Factory(ecc);

// Enum for attestation statuses
const AttestationStatus = {
  INITIATED: 'INITIATED',
  ATTESTED: 'ATTESTED',  // Only two statuses now
};

// Updated MutualAttestation class with HD key derivation using commitmentId
class MutualAttestation {
    constructor(mnemonic, participantName) {
      this.name = participantName;
      this.masterNode = this.getMasterNodeFromMnemonic(mnemonic);
      this.attestedAssets = new Map(); // Store attested assets
    }
  
    // Generate master node from mnemonic
    getMasterNodeFromMnemonic(mnemonic) {
      if (!bip39.validateMnemonic(mnemonic)) {
        throw new Error('Invalid mnemonic');
      }
      const seed = bip39.mnemonicToSeedSync(mnemonic);
      return bip32.fromSeed(seed);
    }
  
    // Derive key pair using commitmentId
    getKeyPairFromCommitmentId(commitmentId) {
      const derivationPath = `m/44'/60'/0'/0/${parseInt(commitmentId, 10)}`;
      const derivedNode = this.masterNode.derivePath(derivationPath);
  
      if (!derivedNode.privateKey) {
        throw new Error('Failed to derive private key');
      }
  
      const ecdsa = new ec('secp256k1');
      return ecdsa.keyFromPrivate(derivedNode.privateKey.toString('hex'));
    }
  
    // Generate a unique hash for an asset
    generateAssetHash(asset) {
      const assetString = JSON.stringify(asset);
      return crypto.createHash('sha256').update(assetString).digest('hex');
    }
  
    // Sign an asset with HD key derived using commitmentId
    signAsset(asset, initialStatus = AttestationStatus.INITIATED) {
      const assetHash = this.generateAssetHash(asset);
      const commitmentId = asset.commitmentId;
      const keyPair = this.getKeyPairFromCommitmentId(commitmentId);
      const signature = keyPair.sign(assetHash).toDER('hex');
  
      return {
        asset: asset,
        assetHash: assetHash,
        signature: signature,
        status: initialStatus,
        participantSignatures: [{
          participant: this.name,
          signature: signature,
          timestamp: Date.now(),
        }],
        history: [`Asset initiated by ${this.name}`]
      };
    }
  
    // Verify an asset's signature
    verifyAssetSignature(attestation, otherKeyPair) {
      try {
        const verificationHash = this.generateAssetHash(attestation.asset);
        return otherKeyPair.verify(verificationHash, attestation.signature);
      } catch (error) {
        console.error('Verification failed:', error);
        return false;
      }
    }
  
    // Mutually attest an asset with another participant
    mutuallyAttest(otherParticipant, asset) {
      const existingAttestation = this.attestedAssets.get(otherParticipant.name);
  
      let attestation;
      if (!existingAttestation) {
        attestation = this.signAsset(asset);
      } else {
        attestation = existingAttestation;
  
        if (attestation.status === AttestationStatus.ATTESTED) {
          console.log(`Asset is already attested between ${this.name} and ${otherParticipant.name}`);
          return attestation;
        }
      }
  
      const mySignature = this.getKeyPairFromCommitmentId(asset.commitmentId)
        .sign(attestation.assetHash)
        .toDER('hex');
  
      attestation.participantSignatures.push({
        participant: this.name,
        signature: mySignature,
        timestamp: Date.now()
      });
  
      attestation.status = AttestationStatus.ATTESTED;
      attestation.history.push(`Asset attested between ${this.name} and ${otherParticipant.name}`);
  
      const isAccepted = otherParticipant.receiveAttestation(this, attestation);
  
      if (isAccepted) {
        this.attestedAssets.set(otherParticipant.name, attestation);
      }
  
      return attestation;
    }
  
    // Receive and validate an attestation
    receiveAttestation(fromParticipant, attestation) {
      const isValid = this.verifyAssetSignature(
        attestation,
        fromParticipant.getKeyPairFromCommitmentId(attestation.asset.commitmentId)
      );
  
      if (isValid) {
        console.log(`Valid attestation received from ${fromParticipant.name}`);
        this.attestedAssets.set(fromParticipant.name, attestation);
        return true;
      } else {
        console.log(`Invalid attestation from ${fromParticipant.name}`);
        return false;
      }
    }
  
    // Retrieve all attestations
    getAllAttestations() {
      return Object.fromEntries(this.attestedAssets);
    }
  }
  
  // Demonstration function
  function demonstrateAttestationWithHDKeys() {
    console.log("\n--- Mutual Attestation with HD Key Derivation ---");
  
    const supplier = new MutualAttestation(
      "empty expose treat boss purchase someone dawn later fat icon exile broccoli", 
      "Supplier"
    );
  
    const buyer = new MutualAttestation(
      "universe pulse thank truth rescue business elite seed grab black repair trim", 
      "Buyer"
    );
  
    const supplyContract = {
      commitmentId: "1",
      description: "Advanced Technology Supply Agreement",
      terms: {
        quantity: 1000,
        unitPrice: 500,
        totalValue: 500000,
        deliveryDate: "2024-06-30"
      }
    };
  
    console.log("Supplier initiates attestation...");
    const supplierAttestation = supplier.mutuallyAttest(buyer, supplyContract);
  
    console.log("Buyer responds and attests...");
    const buyerAttestation = buyer.mutuallyAttest(supplier, supplyContract);
  
    console.log("\nSupplier's Attestation:");
    console.log(JSON.stringify(supplier.getAllAttestations(), null, 2));
  
    console.log("\nBuyer's Attestation:");
    console.log(JSON.stringify(buyer.getAllAttestations(), null, 2));
  }
  
  // Run demonstration
  demonstrateAttestationWithHDKeys();
