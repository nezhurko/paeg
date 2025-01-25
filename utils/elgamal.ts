import { generateKeyPairSync, generatePrimeSync } from "node:crypto";
import { modPow } from "./math";
import { bigintToString, stringToBigInt } from "./rsa";

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


//test
const keypair = generateKeypairElGamal();
const message = 'Hello, world!';

const encrypted = encrypt(message, keypair.publicKey);
const decrypted = decrypt(encrypted, keypair.privateKey.x, keypair.publicKey.p);

console.log(`Original message: ${message}`);
console.log(encrypted);
console.log(`Decrypted message: ${decrypted}`);