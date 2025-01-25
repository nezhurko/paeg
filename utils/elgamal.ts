import { generateKeyPairSync, generatePrimeSync } from "node:crypto";
import { modPow } from "./math";
import { bigintToString, stringToBigInt } from "./rsa";
import { ElGamal, genElGamalParams } from 'micro-rsa-dsa-dh/elgamal.js';

function generateKeypairElGamal() {
    const params = genElGamalParams(256);
    const elgamal = ElGamal(params);

    const privateKey = elgamal.randomPrivateKey();
    const publicKey = elgamal.getPublicKey(privateKey);

    return { publicKey, privateKey };
}

function encrypt(message: string, publicKey: { p: bigint, g: bigint, y: bigint }) {
    const k = BigInt(Math.floor(Math.random() * Number(publicKey.p - 2n))) + 1n;

    const a = modPow(publicKey.g, k, publicKey.p);
    const b = stringToBigInt(message) * modPow(publicKey.y, k, publicKey.p) % publicKey.p;

    return { a, b };
}

function decrypt(encrypted: { a: bigint, b: bigint }, privateKey: bigint, p: bigint) {
    const s = modPow(encrypted.a, p - 1n - privateKey, p);
    const decrypted = encrypted.b * s % p;

    return bigintToString(decrypted);
}

export { generateKeypairElGamal, encrypt, decrypt };

console.log(generateKeypairElGamal());

//test
// const keypair = generateKeypairElGamal();
// const message = 'Hello, world!';

// const encrypted = encrypt(message, keypair.publicKey);
// const decrypted = decrypt(encrypted, keypair.privateKey.x, keypair.publicKey.p);

// console.log(`Original message: ${message}`);
// console.log(encrypted);
// console.log(`Decrypted message: ${decrypted}`);