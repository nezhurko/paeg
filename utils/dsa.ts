import { createSign, createVerify, generateKeyPairSync, generatePrime, generatePrimeSync, KeyLike, randomBytes, randomInt } from "node:crypto";
import { modPow } from "./math";

function randomBigInt(max: bigint | number) {
    let bytes = Math.ceil(max.toString(2).length / 8);
    let randomValue;
    do {
        randomValue = BigInt('0x' + randomBytes(bytes).toString('hex'));
    } while (randomValue >= max);
    return randomValue;
}

function generateKeypairDSA() {
    return generateKeyPairSync('dsa', {
        modulusLength: 2048,
        divisorLength: 256
    });
}

function sign(message: string, privateKey: KeyLike){
    const signer = createSign('SHA256');

    signer.update(message);
    signer.end();

    return signer.sign(privateKey, 'base64');
}

function verify(signature: string, message: string, publicKey: KeyLike){
    const verifier = createVerify('SHA256');
    verifier.update(message);
    verifier.end();
    return verifier.verify(publicKey, signature, 'base64');
}

// function generateKeypairDSA() {
//     const q = generatePrimeSync(256, { bigint: true });

//     let p;
//     do {
//         const randomOffset = BigInt(Math.floor(Math.random() * 1000)) * q;
//         p = generatePrimeSync(2048, { bigint: true, add: randomOffset, rem: q });
//     } while ((p - 1n) % q !== 0n);

//     let g;
//     do {
//         const h = randomBigInt(p - 1n) + 1n;
//         g = modPow(h, (p - 1n) / q, p);
//     } while (g <= 1n);

//     const x = randomBigInt(q); // Private key
//     const y = modPow(g, x, p); // Public key part

//     return {
//         publicKey: { p, q, g, y },
//         privateKey: { x }
//     };
// }

// function sign(message: bigint, privateKey: bigint, publicKey: { p: bigint, q: bigint, g: bigint }) {
//     let k;
//     do{
//         k = BigInt(Math.floor(Math.random() * Number(publicKey.q)));
//     }while(k === 0n);

//     const r = modPow(publicKey.g, k, publicKey.p) % publicKey.q;

//     const s = modPow(k, -1n, publicKey.q) * (message + privateKey * r) % publicKey.q;

//     return { r, s };
// }

// function verify(signature: { r: bigint, s: bigint }, message: bigint, publicKey: { p: bigint, q: bigint, g: bigint, y: bigint }) {
//     if(signature.r <= 0n || signature.r >= publicKey.q || signature.s <= 0n || signature.s >= publicKey.q)return false;

//     const w = modPow(signature.s, -1n, publicKey.q);
//     const u1 = message * w % publicKey.q;
//     const u2 = signature.r * w % publicKey.q;

//     const v = (modPow(publicKey.g, u1, publicKey.p) * modPow(publicKey.y, u2, publicKey.p)) % publicKey.p % publicKey.q;

//     return v === signature.r;
// }

export { generateKeypairDSA, sign, verify };