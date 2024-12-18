  const bip39 = require('bip39');
  const ecc = require('tiny-secp256k1');
  const { BIP32Factory } = require('bip32');
  const crypto = require('crypto');
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
      return node.neutered().toBase58();
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

      // Store public keys directly
      this.committeePublicKey = this.derivePublicKey(creator.mnemonic);
      this.committerPublicKey = this.derivePublicKey(committer.mnemonic);

      // this.committeeXpubkey = creator.xpubkey;
      // this.committerXpubkey = committer.xpubkey;

      // Derive commitment xpubkey using the commitmentId in the derivation path
      this.commitmentXpubkey = this.deriveCommitmentXpubKey(creator.xpubkey, this.commitmentId);

      Commitment.commitments.push(this);
    }

    // Method to derive a public key from a mnemonic
    derivePublicKey(mnemonic) {
      const seed = bip39.mnemonicToSeedSync(mnemonic);
      const node = bip32.fromSeed(seed);
      // Use a non-hardened derivation path
      const derivedNode = node.derive(0).derive(0);
      return derivedNode.publicKey;
    }

    deriveCommitmentXpubKey(creatorXpubkey, commitmentId) {
      const seed = bip39.mnemonicToSeedSync(creatorXpubkey);
      const node = bip32.fromSeed(seed);

      // Derive commitment public key from xpub and commitmentId
      const commitmentPath = `m/44'/60'/0'/0/${commitmentId}`;
      const commitmentNode = node.derivePath(commitmentPath);
      return commitmentNode.neutered().toBase58();
    }

    static listCommitments() {
      return Commitment.commitments;
    }

    signCommitment(userId, mnemonic) {
      const user = Users.findById(userId);
      if (!user) throw new Error('User not found');

      const seed = bip39.mnemonicToSeedSync(mnemonic);
      const node = bip32.fromSeed(seed);

      // Derive the private key for signing using a non-hardened path
      const privateKeyNode = node.derive(0).derive(0);
      const privateKey = privateKeyNode.privateKey;
      if (!privateKey) throw new Error('Failed to derive private key');

      // Create a hash of the commitment
      const hash = crypto.createHash('sha256')
        .update(JSON.stringify(this.assetPayload))
        .digest();

      // Generate the signature
      const signature = ecc.sign(hash, privateKey);

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
      // Determine which public key to use based on user role
      let publicKey;
      if (userId === this.creatorId) {
        publicKey = this.committeePublicKey;
      } else if (userId === this.committerId) {
        publicKey = this.committerPublicKey;
      } else {
        throw new Error('User is neither the creator nor the committer');
      }

      // Create a hash of the commitment payload
      const hash = crypto.createHash('sha256')
        .update(JSON.stringify(this.assetPayload))
        .digest();
      
      // Verify signature using the stored public key
      return ecc.verify(hash, publicKey, signature);
    }

    dischargeCommitment() {
      // Check if both signatures are valid
      if (!this.committeeSignature || !this.committerSignature) {
        throw new Error('Cannot discharge: Missing signatures');
      }

      // Verify both signatures
      const committeeSignatureValid = this.verifyCommitmentSignature(this.creatorId, this.committeeSignature);
      const committerSignatureValid = this.verifyCommitmentSignature(this.committerId, this.committerSignature);

      // Only discharge if both signatures are valid
      if (committeeSignatureValid && committerSignatureValid) {
        this.status = 'DISCHARGED';
        return true;
      } else {
        throw new Error('Cannot discharge: Invalid signatures');
      }
    }
    
    getStatus() {
      return {
        commitmentId: this.commitmentId,
        status: this.status,
        assetPayload: this.assetPayload
      }
    }

    
  }

  // Generate mnemonics for users
  const mnemonicAlice = bip39.generateMnemonic();
  const mnemonicBob = bip39.generateMnemonic();

  // Add users
  const alice = new Users(mnemonicAlice, 'Alice');
  const bob = new Users(mnemonicBob, 'Bob');

  // Create a commitment
  const commitment = new Commitment(1, 2, { assetName: 'Gold', quantity: 100, unit: 'grams' });

  // Sign the commitment
  commitment.signCommitment(1, mnemonicAlice); // Committee signs
  commitment.signCommitment(2, mnemonicBob);  // Committer signs

  console.log("Mnemonics:");
  console.log("Alice's Mnemonic:", mnemonicAlice);
  console.log("Bob's Mnemonic:", mnemonicBob);

  console.log("\nAll Users:");
  console.log(Users.listUsers());

  console.log("\nAll Commitments:");
  console.log(Commitment.listCommitments());

  // Verify signatures
  const committeeSignatureValid = commitment.verifyCommitmentSignature(1, commitment.committeeSignature);
  console.log('Updated Status:', commitment.getStatus());
  const committerSignatureValid = commitment.verifyCommitmentSignature(2, commitment.committerSignature);

  console.log('\nCommittee Signature Valid:', committeeSignatureValid);
  console.log('Committer Signature Valid:', committerSignatureValid);

  commitment.dischargeCommitment();
  console.log('Updated Status:', commitment.getStatus());
