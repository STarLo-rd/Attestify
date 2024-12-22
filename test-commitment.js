const bip39 = require('bip39');
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const crypto = require('crypto');

const bip32 = BIP32Factory(ecc);

// Mock Users class for testing
class Users {
    static findById(id) {
        const testUsers = { 
            1: {
                id: 1,
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                xpubkey: "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
            },
            2: {
                id: 2,
                mnemonic: "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                xpubkey: "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz"
            }
        };
        return testUsers[id];
    }
}

class Commitment {
    constructor(creatorId, committerId, commitmentId, assetPayload) {
        this.creatorId = creatorId;
        this.committerId = committerId;
        this.commitmentId = commitmentId;
        this.assetPayload = assetPayload;
        this.status = 'PENDING';
        
        // Initialize commitment
        const creator = Users.findById(creatorId);
        const committer = Users.findById(committerId);
        
        if (!creator || !committer) {
            throw new Error("Both creator and committer must be valid users");
        }

        this.committeeXpubkey = this.deriveCommitmentXpubKey(creator.xpubkey, this.commitmentId);
        this.committerXpubkey = this.deriveCommitmentXpubKey(committer.xpubkey, this.commitmentId);
    }

    deriveCommitmentXpubKey(parentXpubkey, commitmentId) {
        try {
            const node = bip32.fromBase58(parentXpubkey); // Must be the master key
            const commitmentPath = `m/44'/60'/0'/0/${commitmentId}`; // Correct path
            const commitmentNode = node.derivePath(commitmentPath); // Derive correctly
            return commitmentNode.neutered().toBase58(); // Return the neutered (xpub) key
        } catch (error) {
            throw new Error(`Failed to derive commitment xpubkey: ${error.message}`);
        }
    }
    

    signCommitment(userId, mnemonic) {
        const user = Users.findById(userId);
        if (!user) throw new Error('User not found');

        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const node = bip32.fromSeed(seed);
        const commitmentPath = `m/44'/60'/0'/0/${this.commitmentId}`;
        const privateKeyNode = node.derivePath(commitmentPath);
        const privateKey = privateKeyNode.privateKey;
        
        if (!privateKey) throw new Error('Failed to derive private key');

        const hash = crypto.createHash('sha256')
            .update(JSON.stringify(this.assetPayload))
            .digest();
        
        const signature = Buffer.from(ecc.sign(hash, privateKey));

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
        let xpubkey;
    
        if (userId === this.creatorId) {
            xpubkey = Users.findById(this.creatorId).xpubkey;
        } else if (userId === this.committerId) {
            xpubkey = Users.findById(this.committerId).xpubkey;
        } else {
            throw new Error('User is neither the creator nor the committer');
        }
    
        try {
            const node = bip32.fromBase58(xpubkey); // Must be master xpub
            const commitmentPath = `m/44'/60'/0'/0/${this.commitmentId}`; // Match signing path
            const derivedNode = node.derivePath(commitmentPath);
            const publicKey = derivedNode.publicKey; // Extract the public key
    
            const hash = crypto.createHash('sha256')
                .update(JSON.stringify(this.assetPayload))
                .digest();
    
            const isValid = ecc.verify(hash, publicKey, signature);
    
            return isValid;
        } catch (error) {
            console.error('Verification failed:', error.message);
            return false;
        }
    }
    
    
    
}

// Test script
async function runTests() {
    console.log('Starting commitment tests...');

    try {
        // Test data
        const creatorId = 1;
        const committerId = 2;
        const commitmentId = 123;
        const assetPayload = {
            type: "TEST_ASSET",
            value: 1000,
            timestamp: Date.now()
        };

        // Create commitment
        console.log('\nCreating new commitment...');
        const commitment = new Commitment(creatorId, committerId, commitmentId, assetPayload);
        console.log('Commitment created successfully');

        // Test creator signing
        console.log('\nTesting creator signature...');
        const creator = Users.findById(creatorId);
        commitment.signCommitment(creatorId, creator.mnemonic);
        const creatorVerification = commitment.verifyCommitmentSignature(
            creatorId, 
            commitment.committeeSignature
        );
        console.log('Creator signature verification:', creatorVerification);

        // Test committer signing
        console.log('\nTesting committer signature...');
        const committer = Users.findById(committerId);
        commitment.signCommitment(committerId, committer.mnemonic);
        const committerVerification = commitment.verifyCommitmentSignature(
            committerId, 
            commitment.committerSignature
        );
        console.log('Committer signature verification:', committerVerification);

        // Test final status
        console.log('\nFinal commitment status:', commitment.status);
        
        // Test invalid user
        console.log('\nTesting invalid user...');
        try {
            commitment.verifyCommitmentSignature(999, Buffer.from('invalid'));
        } catch (error) {
            console.log('Invalid user test passed:', error.message);
        }

    } catch (error) {
        console.error('Test failed:', error);
    }
}

// Run the tests
runTests().then(() => console.log('\nTests completed'));