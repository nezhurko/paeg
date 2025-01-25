//blum blum shub utils

import { generatePrimeSync, randomBytes, randomInt } from "node:crypto";
import { stringToBigInt } from "./rsa";

function randomBigInt(min: bigint, max: bigint) {
    let range = max - min;
    const bytesToGenerate = Math.ceil(range.toString(2).length / 8);
    let randomByt = randomBytes(bytesToGenerate);
    let randomBigInt = BigInt('0x' + randomByt.toString('hex'));

    // Reduce 'randomBigInt' to be within the range
    return min + (randomBigInt % (range + 1n));
}

function generateKeypairBBS(p?: bigint, q?: bigint){
    let p_ = p;
    let q_ = q;

    if(!p_ || !p_){
        p_ = generatePrimeSync(512, { bigint: true });
        q_ = generatePrimeSync(512, { bigint: true });
    }

    let n = p_ * q_;

    return {
        publicKey: { n },
        privateKey: { 
            p: p_,
            q: q_
         }
    };
}

function bbsGenerate(seed: bigint, publicKey: { n: bigint }, length: number) {
    let x = (seed * seed) % publicKey.n;
    const bits = [];
    for (let i = 0; i < length; i++) {
        x = (x * x) % publicKey.n;
        bits.push(x % 2n);
    }
    return bits;
}

function xorBinary(a: bigint[], b: bigint[]): bigint[] {
    let result = [];

    if (a.length !== b.length) {
        throw new Error("Arrays must be of the same length");
    }

    for (let i = 0; i < a.length; i++) {
        result.push(a[i] ^ b[i]);
    }
    return result;
}

function encryptBBS(message: string, publicKey: { n: bigint }, seed: bigint) {
    const bits = textToBinary(message);

    const keyBits = bbsGenerate(seed, publicKey, bits.length);

    const encryptedBits = xorBinary(bits, keyBits);

    return {
        encryptedBits,
        keyBits
    };
}

function decryptBBS(encryptedBits: bigint[], keyBits: bigint[]) {
    const decryptedBits = xorBinary(encryptedBits, keyBits);
    return {
        decrypted: binaryToText(decryptedBits)
    }
}

function textToBinary(text: string) {
    return text.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join('').split('').map(bit => BigInt(bit));
}

function binaryToText(bits: bigint[]): string {
    let binary = bits.map(bit => Number(bit).toString()).join('');
    let text = '';
    for (let i = 0; i < binary.length; i += 8) {
        let byte = binary.slice(i, i + 8);
        text += String.fromCharCode(parseInt(byte, 2));
    }
    return text;
}

function bitsToString(bitsArray: bigint[]) {
    return bitsArray.map(bit => bit.toString()).join('');
}

function stringToBits(string: string) {
    return Array.from(string).map(char => BigInt(char));
  }

export { generateKeypairBBS, encryptBBS, decryptBBS, bbsGenerate, bitsToString, stringToBits };



//test
// const keypair = generateKeypairBBS();

// const text = 'Hello, World!';

// const encrypted = encryptBBS(text, keypair.publicKey, BigInt(123));

// console.log(bitsToString(encrypted.encryptedBits));

// const decrypted = decryptBBS(encrypted.encryptedBits, encrypted.keyBits);

// console.log(decrypted);