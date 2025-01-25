import { generateKeyPairSync, generatePrimeSync, randomBytes, randomInt } from "node:crypto";
import { modPow } from "./math";
import { bigintToString, stringToBigInt } from "./rsa";

function randomBigInt(max: bigint | number) {
    let bytes = Math.ceil(max.toString(2).length / 8);
    let randomValue;
    do {
        randomValue = BigInt('0x' + randomBytes(bytes).toString('hex'));
    } while (randomValue >= max);
    return randomValue;
}

function generateKeypairElGamal() {
    const p = generatePrimeSync(1024, { bigint: true });

    let g;

    do {
        g = BigInt(Math.floor(Math.random() * Number(p - 1n))) + 1n;
    } while (g <= 1n || g >= p - 1n);

    const x = BigInt(Math.floor(Math.random() * Number(p - 2n))) + 1n;

    const y = modPow(g, x, p);

    return {
        publicKey: { p, g, y },
        privateKey: { x }
    };
}

function encryptChunk(chunk, publicKey) {
    const k = BigInt((Number(publicKey.p - 2n))) + 1n;
    const a = modPow(publicKey.g, k, publicKey.p);
    const b = stringToBigInt(chunk) * modPow(publicKey.y, k, publicKey.p) % publicKey.p;
    return { a, b };
}

function decryptChunk({ a, b }, privateKey, p) {
    const s = modPow(a, p - 1n - privateKey, p);
    return bigintToString(b * s % p);
}

function encrypt(message, publicKey) {
    const chunkSize = 10;
    const chunks = [];
    for (let i = 0; i < message.length; i += chunkSize) {
        const chunk = message.substring(i, i + chunkSize);
        chunks.push(encryptChunk(chunk, publicKey));
    }
    return chunks;
}

function decrypt(chunks, privateKey, p) {
    return chunks.map(chunk => decryptChunk(chunk, privateKey, p)).join('');
}

export { generateKeypairElGamal, encrypt, decrypt };


//test
// const keypair = generateKeypairElGamal();
// const message = 'Hello, world! This is a longer test message to check chunk encryption.';

// const encrypted = encrypt(message, keypair.publicKey);
// const decrypted = decrypt(encrypted, keypair.privateKey.x, keypair.publicKey.p);

// console.log(`Original message: ${message}`);
// console.log(encrypted);
// console.log(`Decrypted message: ${decrypted}`);