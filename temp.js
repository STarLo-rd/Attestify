const bip39 = require('bip39');
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const crypto = require('crypto');
const secp256k1 = require('secp256k1'); // Ensure you have this dependency installed
const bip32 = BIP32Factory(ecc);

class Users {
  static userId = 0;
  static users = [];
  
  constructor(mnemonic, name) {
    this.id = ++Users.userId;
    this.name = name;
    this.mnemonic = mnemonic;
    this.xpubkey = this.deriveXpubKey(mnemonic);
    Users.users.push(this);
  }

  deriveXpubKey(mnemonic) {
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const node = bip32.fromSeed(seed);
    return node.neutered().toBase58(); // Neutered means xpubkey (no private key access)
  }

  static listUsers() {
    return Users.users.map(user => ({
      id: user.id,
      name: user.name,
      xpubkey: user.xpubkey,
    }));
  }

  static findById(id) {
    return Users.users.find(user => user.id === id);
  }
}

class Commitment {
  static commitments = [];
  static commitmentId = 0;

  constructor(creatorId, committerId, assetPayload) {
    this.commitmentId = ++Commitment.commitmentId;
    this.creatorId = creatorId;
    this.committerId = committerId;
    this.assetPayload = assetPayload;
    this.status = 'INITIATED';
    this.committeeSignature = null;
    this.committerSignature = null;

    const creator = Users.findById(creatorId);
    const committer = Users.findById(committerId);

    if (!creator || !committer) {
      throw new Error("Both creator and committer must be valid users");
    }

    this.committeeXpubkey = creator.xpubkey;
    this.committerXpubkey = committer.xpubkey;

    // Derive commitment xpubkey using the commitmentId in the derivation path
    this.commitmentXpubkey = this.deriveCommitmentXpubKey(creator.xpubkey, this.commitmentId);

    Commitment.commitments.push(this);
  }

  deriveCommitmentXpubKey(creatorXpubkey, commitmentId) {
    const seed = bip39.mnemonicToSeedSync(creatorXpubkey); // Use creator's mnemonic to derive seed
    const node = bip32.fromSeed(seed);

    // Derive commitment public key from xpub and commitmentId
    const commitmentPath = `m/44'/60'/0'/0/${commitmentId}`;
    const commitmentNode = node.derivePath(commitmentPath);
    return commitmentNode.neutered().toBase58(); // Return the derived xpubkey for the commitment
  }

  static listCommitments() {
    return Commitment.commitments;
  }

  signCommitment(userId, mnemonic) {
    const user = Users.findById(userId);
    if (!user) throw new Error('User not found');

    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const node = bip32.fromSeed(seed);

    // Derive the private key for signing
    const privateKey = node.derivePath("m/0").privateKey;
    if (!privateKey) throw new Error('Failed to derive private key');

    // Create a hash of the commitment
    const hash = crypto.createHash('sha256').update(JSON.stringify(this.assetPayload)).digest();

    // Generate the signature
    const signature = ecc.sign(hash, privateKey).toString('hex');

    // Add signature based on the user role
    if (userId === this.creatorId) {
      this.committeeSignature = signature;
    } else if (userId === this.committerId) {
      this.committerSignature = signature;
    } else {
      throw new Error('User is neither the creator nor the committer');
    }

    if (this.committeeSignature && this.committerSignature) {
      this.status = 'ACKNOWLEDGED';
    }
  }
  verifyCommitmentSignature(userId, signature) {
    const user = Users.findById(userId);
    if (!user) throw new Error('User not found');
  
    const seed = bip39.mnemonicToSeedSync(user.mnemonic);
    const node = bip32.fromSeed(seed);
  
    // Derive the public key for the user
    const publicKey = node.derivePath("m/0").publicKey;
  
    // Convert signature string to Buffer if it's a comma-separated string of numbers
    const signatureBuffer = typeof signature === 'string' 
      ? Buffer.from(signature.split(',').map(Number)) 
      : signature;
  
    // Create a hash of the commitment
    const hash = crypto.createHash('sha256').update(JSON.stringify(this.assetPayload)).digest();
    
    // Use tiny-secp256k1 for verification
    const isValid = ecc.verify(hash, publicKey, signatureBuffer);
    
    return isValid;
  }
}

// Input mnemonics for users
const mnemonicAlice = bip39.generateMnemonic();
const mnemonicBob = bip39.generateMnemonic();

// Add users
new Users(mnemonicAlice, 'Alice');
new Users(mnemonicBob, 'Bob');

// Create a commitment
const commitment = new Commitment(1, 2, { assetName: 'Gold', quantity: 100, unit: 'grams' });

// Sign the commitment
commitment.signCommitment(1, mnemonicAlice); // Committee signs
commitment.signCommitment(2, mnemonicBob);  // Committer signs
console.log("All Users:");
console.log(Users.listUsers());

console.log("All Commitments:");
console.log(Commitment.listCommitments());

// Verify signatures
const committeeSignatureValid = commitment.verifyCommitmentSignature(1, commitment.committeeSignature);
const committerSignatureValid = commitment.verifyCommitmentSignature(2, commitment.committerSignature);


console.log('Committee Signature Valid:', committeeSignatureValid);
console.log('Committer Signature Valid:', committerSignatureValid);

