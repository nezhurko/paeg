import { generateKeypairElGamal, signElGamal, verifyElGamal } from "./utils/elgamal";
import { generateRandomByCiphers } from "./utils/math";
// import { decryptRSA, encryptRSA, generateRSAKeyPair } from "./utils/rsa_v2";
import { generateKeypair, encrypt, decrypt, stringToBigInt, sign } from "./utils/rsa";

const candidates = [
    'c1',
    'c2',
];

const voters: any = {
    A: {
        rsaKeypair: generateKeypair(),
        elgamalKeypair: generateKeypairElGamal()
    },
    B: {
        rsaKeypair: generateKeypair(),
        elgamalKeypair: generateKeypairElGamal()
    },
    C: {
        rsaKeypair: generateKeypair(),
        elgamalKeypair: generateKeypairElGamal()
    },
    D: {
        rsaKeypair: generateKeypair(),
        elgamalKeypair: generateKeypairElGamal()
    }
};

// Кожен виборець формує свій Е-бюлетень, після чого робить наступне:
// o Додає до свого Е-бюлетеня довільний рядок, зберігає рядок.
// o Шифрує результати попереднього етапу відкритим ключем D.
// o Шифрує результати попереднього етапу відкритим ключем C.
// o Шифрує результати попереднього етапу відкритим ключем B.
// o Шифрує результати попереднього етапу відкритим ключем A.

let encryptedMessagesList1: bigint[] = [];

Object.keys(voters).forEach((voterId) => {
    const voter = voters[voterId];
    
    const chose = candidates[Math.floor(Math.random() * candidates.length)];

    const message = `${chose}${voterId}${generateRandomByCiphers(1)}`;

    let encryptedMessage1: bigint = encrypt(stringToBigInt(message), voters[Object.keys(voters)[0]].rsaKeypair.publicKey);

    for (let i = 1; i < Object.keys(voters).length; i++) {
        encryptedMessage1 = encrypt(stringToBigInt(message), voters[Object.keys(voters)[i]].rsaKeypair.publicKey);
    }

    let encryptedMessage2 = encryptedMessage1;

    for (let i = 1; i < Object.keys(voters).length; i++) {
        encryptedMessage2 = encrypt(stringToBigInt(`${encryptedMessage2}`), voters[Object.keys(voters)[i]].rsaKeypair.publicKey);
    }

    encryptedMessagesList1.push(encryptedMessage2);
});

console.log(encryptedMessagesList1);

let [
    decryptedA,
    decryptedB,
    decryptedC,
    decryptedD
]: bigint[][] = [[], [], [], []];

//A
(() => {
    const voter = voters['A'];

    encryptedMessagesList1.forEach((encryptedMessage) => {
        decryptedA.push(decrypt(encryptedMessage, voter.rsaKeypair.privateKey));
    });

    decryptedA = decryptedA.sort(() => Math.random() - 0.5);
})();

//B
(() => {
    const voter = voters['B'];

    decryptedA.forEach((encryptedMessage) => {
        decryptedB.push(decrypt(encryptedMessage, voter.rsaKeypair.privateKey));
    });

    decryptedB = decryptedB.sort(() => Math.random() - 0.5);
})();

//C
(() => {
    const voter = voters['C'];

    decryptedB.forEach((encryptedMessage) => {
        decryptedC.push(decrypt(encryptedMessage, voter.rsaKeypair.privateKey));
    });

    decryptedC = decryptedC.sort(() => Math.random() - 0.5);
})();

//D
(() => {
    const voter = voters['D'];

    decryptedC.forEach((encryptedMessage) => {
        decryptedD.push(decrypt(encryptedMessage, voter.rsaKeypair.privateKey));
    });

    decryptedD = decryptedD.sort(() => Math.random() - 0.5);
})();

let [
    decryptedA2,
    decryptedB2,
    decryptedC2,
    decryptedD2
]: Array<{ message: bigint, signature: { r: bigint, s: bigint } }>[] = [[], [], [], []];

//A2
(() => {
    const voter = voters['A'];

    decryptedD.forEach((encryptedMessage) => {
        const messageA2 = decrypt(encryptedMessage, voter.rsaKeypair.privateKey);
        decryptedA2.push({
            message: messageA2,
            signature: signElGamal(messageA2, voter.elgamalKeypair.privateKey.x, voter.elgamalKeypair.publicKey.p, voter.elgamalKeypair.publicKey.g)
        });
    });

    decryptedA2 = decryptedA2.sort(() => Math.random() - 0.5);
})();

//B2
(() => {
    const voter = voters['B'];

    decryptedA2.forEach((encryptedMessage) => {
        if(!verifyElGamal(encryptedMessage.message, encryptedMessage.signature, voters['A'].elgamalKeypair.publicKey)){
            throw new Error('Invalid A signature');
        }

        const messageB2 = decrypt(encryptedMessage.message, voter.rsaKeypair.privateKey);
        decryptedB2.push({
            message: messageB2,
            signature: signElGamal(messageB2, voter.elgamalKeypair.privateKey.x, voter.elgamalKeypair.publicKey.p, voter.elgamalKeypair.publicKey.g)
        });
    });

    decryptedB2 = decryptedB2.sort(() => Math.random() - 0.5);
})();

//C2
(() => {
    const voter = voters['C'];

    decryptedB2.forEach((encryptedMessage) => {
        if(!verifyElGamal(encryptedMessage.message, encryptedMessage.signature, voters['B'].elgamalKeypair.publicKey)){
            throw new Error('Invalid B signature');
        }

        const messageC2 = decrypt(encryptedMessage.message, voter.rsaKeypair.privateKey);
        decryptedC2.push({
            message: messageC2,
            signature: signElGamal(messageC2, voter.elgamalKeypair.privateKey.x, voter.elgamalKeypair.publicKey.p, voter.elgamalKeypair.publicKey.g)
        });
    });

    decryptedC2 = decryptedC2.sort(() => Math.random() - 0.5);
})();

//D2
(() => {
    const voter = voters['D'];

    decryptedC2.forEach((encryptedMessage) => {
        if(!verifyElGamal(encryptedMessage.message, encryptedMessage.signature, voters['C'].elgamalKeypair.publicKey)){
            throw new Error('Invalid C signature');
        }

        const messageD2 = decrypt(encryptedMessage.message, voter.rsaKeypair.privateKey);
        decryptedD2.push({
            message: messageD2,
            signature: signElGamal(messageD2, voter.elgamalKeypair.privateKey.x, voter.elgamalKeypair.publicKey.p, voter.elgamalKeypair.publicKey.g)
        });
    });

    decryptedD2 = decryptedD2.sort(() => Math.random() - 0.5);
})();

const finalResults = decryptedD2.map((encryptedMessage) => {
    if(!verifyElGamal(encryptedMessage.message, encryptedMessage.signature, voters['D'].elgamalKeypair.publicKey)){
        throw new Error('Invalid D signature');
    }

    return encryptedMessage.message;
});

console.log(finalResults);