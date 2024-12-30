# Attestation SDK

A TypeScript SDK for managing digital payment commitments using hierarchical deterministic (HD) wallets and cryptographic attestations following the BAFT Digital Ledger Payment Commitment protocol.

## Features

- HD wallet support using BIP32/BIP39 standards
- Secure signature creation and verification using secp256k1
- Compatible with external signing services (MetaMask, WalletConnect, etc.)
- Configurable derivation paths for different blockchain standards
- Complete attestation lifecycle management
- State transition validation
- Deterministic child key derivation
- Error handling with detailed messages

## Installation

```bash
npm install attestation-sdk
```

## Technical Overview

The SDK implements a robust attestation system using:

- `tiny-secp256k1` for elliptic curve operations
- `bip32`/`bip39` for HD wallet functionality
- `elliptic` for signature operations
- UUID v4 for unique attestation identifiers

### Core Components

#### Attestation Class

Manages the entire attestation lifecycle with features:

- Deterministic key derivation from xpubs
- State transition management (Initiated → Acknowledged → Effective → Discharged)
- Signature creation and verification
- Secure payload handling

#### SignatureService

Handles cryptographic operations:

- SHA-256 payload hashing
- Signature creation using secp256k1
- Signature verification with public keys
- BN.js for big number operations

## Backend Integration Guide

### Setup

```typescript
// Initialize with your preferred derivation path
const config = {
  ethereum: "m/44'/60'/0'/0",  // Ethereum standard
  cosmos: "m/44'/118'/0'/0",   // Cosmos standard
  custom: "m/44'/999'/0'/0"    // Custom path
};

const attestation = new Attestation(
  committerXpub,
  committeeXpub,
  config.ethereum, // Or your chosen path
  payload,
  "", "", "",
  Attest.INITIATED
);
```

### External Signing Integration

```typescript
// Using MetaMask
async function signWithMetaMask(payload: string) {
  const accounts = await window.ethereum.request({ 
    method: 'eth_requestAccounts' 
  });
  const signature = await window.ethereum.request({
    method: 'personal_sign',
    params: [payload, accounts[0]]
  });
  return signature;
}

// Backend verification
app.post('/verify-attestation', async (req, res) => {
  const { payload, signature, pubKey } = req.body;
  const isValid = SignatureService.verifySignature(
    payload,
    pubKey,
    signature
  );
  return res.json({ isValid });
});
```

### API Implementation Example

```typescript
// Express.js example
import express from 'express';
const app = express();

app.post('/create-attestation', async (req, res) => {
  const { committerXpub, committeeXpub, payload } = req.body;
  
  const attestation = new Attestation(
    committerXpub,
    committeeXpub,
    "m/44'/60'/0'/0",
    payload,
    "", "", "",
    Attest.INITIATED
  );
  
  attestation.initiateAttestation();
  
  // Store attestation details in your database
  await db.attestations.create({
    id: attestation.attestationId,
    state: attestation.commitmentState,
    payload: attestation.attestationPayload
  });
  
  return res.json({
    attestationId: attestation.attestationId,
    status: 'initiated'
  });
});

app.post('/acknowledge-attestation/:id', async (req, res) => {
  const { signature } = req.body;
  const attestation = await getAttestationFromDB(req.params.id);
  
  attestation.setCommitteeSignature(signature);
  attestation.acknowledgeAttestation();
  
  await updateAttestationInDB(attestation);
  
  return res.json({ status: 'acknowledged' });
});
```

## Security

- Implements industry-standard cryptographic protocols
- Validates all state transitions
- Verifies signatures at each stage
- Uses hardened derivation paths
- Enforces secure key handling practices

## Error Handling

Comprehensive error system with:
- Detailed error messages
- Specific error codes
- Type-safe error handling
- State validation checks

## License

MIT

## Contributing

See CONTRIBUTING.md for guidelines.