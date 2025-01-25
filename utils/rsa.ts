import { generatePrimeSync } from "node:crypto";
import { bufferToBigInt, gcd, modInv, modPow } from "./math";

function stringToBigInt(str: string): bigint {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result = (result << 8n) | BigInt(bytes[i]);
    }
    return result;
}

function bigintToString(bigIntValue: bigint): string {
    const bytes: number[] = [];
    while (bigIntValue > 0n) {
        bytes.unshift(Number(bigIntValue & 0xffn)); // Extract the last 8 bits
        bigIntValue >>= 8n; // Shift right to process the next byte
    }
    const decoder = new TextDecoder();
    return decoder.decode(new Uint8Array(bytes));
}

function generateKeypair() {
    const p = generatePrimeSync(2048, {bigint: true});
    const q = generatePrimeSync(2048, {bigint: true});

    const n = p * q;

    const phi = (p - 1n) * (q - 1n);

    let e = 65537n;

    while(gcd(phi, e) !== 1n) {
        e++
    }

    let d = modInv(e, phi);

    return {
        publicKey: {
            n: n,
            e: e
        },
        privateKey: {
            n: n,
            d: d
        }
    }
}

function hash(data: string, n: bigint): bigint {
    let h = 0n;
    for (let i = 0; i < data.length; i++) {
        h += BigInt(data.charCodeAt(i)) ** 2n;    
    }
    return h % n;
}

function sign(hash: bigint, privateKey: {n: bigint, d: bigint}) {
    return modPow(hash, privateKey.d, privateKey.n);
}

function verify(signature: bigint, publicKey: {n: bigint, e: bigint}, hash: bigint) {
    return modPow(signature, publicKey.e, publicKey.n) === hash;
}

//new

function encrypt(message: bigint, publicKey: { n: bigint; e: bigint }) {
    if (message < 0n || message >= publicKey.n) {
        throw new Error("Message out of range: 0 ≤ m < n");
    }
    return modPow(message, publicKey.e, publicKey.n);
}

function decrypt(ciphertext: bigint, privateKey: { n: bigint; d: bigint }) {
    return modPow(ciphertext, privateKey.d, privateKey.n);
}

function generateBlindSignature(message: string, r: bigint, publicKey: { n: bigint; e: bigint }, privateKey: { d: bigint; n: bigint }) {
    const messageBigInt = stringToBigInt(message);

    if (gcd(r, publicKey.n) !== 1n) {
        throw new Error("r must be coprime with n");
    }

    const blindedMessage = modPow(messageBigInt * modPow(r, publicKey.e, publicKey.n), 1n, publicKey.n);
    const blindSignature = modPow(blindedMessage, privateKey.d, privateKey.n);

    return { blindSignature, r };
}

function unblindSignature(blindSignature: bigint, r: bigint, publicKey: { n: bigint }) {
    const rInverse = modInv(r, publicKey.n);
    return (blindSignature * rInverse) % publicKey.n;
}

export { generateKeypair, hash, sign, verify, encrypt, decrypt, generateBlindSignature, unblindSignature, bigintToString, stringToBigInt };

// function test(){
//     const { publicKey, privateKey } = generateKeypair();
//     const data = 'test';
//     const h = hash(data, publicKey.n);
//     const signature = sign(h, privateKey);

//     console.log(verify(signature, publicKey, h));
// }

// test();

// function encode(data: string, recipientPublicKey: {n: bigint, e: bigint}) {
//     const h = hash(data, recipientPublicKey.n);
//     return h ** recipientPublicKey.e % recipientPublicKey.n;
// }

// function decode(encoded: bigint, privateKey: {n: bigint, d: bigint}) {
//     return encoded ** privateKey.d % privateKey.n;
// }

// function sign(data: string, privateKey: {n: bigint, d: bigint}) {
//     const h = hash(data, privateKey.n);
//     return h ** privateKey.d % privateKey.n;
// }

// function verify(data: string, signature: bigint, publicKey: {n: bigint, e: bigint}) {
//     const h = hash(data, publicKey.n);
//     return h === signature ** publicKey.e % publicKey.n;
// }

// function generateKeypair() {
//     const { publicKey, privateKey } = generateKeyPairSync('rsa', {
//         modulusLength: 2048,
//         publicKeyEncoding: {
//             type: 'spki',         // Recommended to use 'spki' for public keys
//             format: 'der'
//         },
//         privateKeyEncoding: {
//             type: 'pkcs8',        // Recommended to use 'pkcs8' for private keys
//             format: 'der'
//         }
//     });

//     return {
//         publicKey: publicKey.toString('base64'),
//         privateKey: privateKey.toString('base64')
//     }
// }

// function signData(data: string, privateKey) {
//     const hash = createHash('sha256').update(data).digest();
//     const signature = sign('sha256', hash, privateKey);
//     return signature;
// }

// function verifySignature(data: string, signature: ArrayBuffer, publicKey: PublicKeyCredentialType) {
//     const hash = createHash('sha256').update(data).digest();
//     return verify('sha256', hash, publicKey, signature);
// }

/*
function test(){
    const { publicKey, privateKey } = generateKeypair();
    const data = 'Hello, world!';
    const signature = signData(data, privateKey);
    console.log(privateKey);
    console.log(verifySignature(data, signature, publicKey));
}

test();
*/