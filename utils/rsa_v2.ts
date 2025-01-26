import { constants, generateKeyPairSync, KeyLike, privateDecrypt, publicEncrypt } from "node:crypto";

function generateRSAKeyPair(publicKeyPath = 'public_key.pem', privateKeyPath = 'private_key.pem') {
    // Generate the key pair
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 20000, // Key size in bits
        publicKeyEncoding: {
            type: 'spki',      // Public key encoding standard
            format: 'pem',     // Format of the public key (PEM)
        },
        privateKeyEncoding: {
            type: 'pkcs8',     // Private key encoding standard
            format: 'pem',     // Format of the private key (PEM)
        },
    });

    return { publicKey, privateKey };
}

function encryptRSA(message: string, publicKey: string){
    const encryptedMessage = publicEncrypt(
        {
            key: publicKey,
            padding: constants.RSA_PKCS1_OAEP_PADDING
        },
        Buffer.from(message)
    )

    return encryptedMessage.toString('base64');
}

function decryptRSA(encryptedMessage: string, privateKey: KeyLike){
    const decryptedMessage = privateDecrypt(
        {
            key: privateKey,
            padding: constants.RSA_PKCS1_OAEP_PADDING
        },
        Buffer.from(encryptedMessage, 'base64')
    )

    return decryptedMessage.toString();
}

export { generateRSAKeyPair, encryptRSA, decryptRSA };

// const keypair = generateRSAKeyPair();

// console.log(keypair);

// const message = 'Hello, World!';

// const encrypted = encryptRSA(message, keypair.publicKey);

// console.log(encrypted);

// const decrypted = decryptRSA(encrypted, keypair.privateKey);

// console.log(decrypted);