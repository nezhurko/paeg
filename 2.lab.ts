// Import required modules
import { generateKeypair, hash, sign, verify, encrypt, decrypt, generateBlindSignature, unblindSignature, bigintToString, stringToBigInt } from "./utils/rsa";
import { gcd, modPow, randomInt } from "./utils/math";

function generateRandomR(n: bigint) {
    const randomBigInt = () => {
        let result = 0n;
        for (let i = 0; i < 8; i++) { // Generate 8 random bytes
            result = (result << 8n) | BigInt(Math.floor(Math.random() * 256));
        }
        return result % (n - 1n) + 1n; // Ensure r is in the range [1, n-1]
    };

    let r;
    do {
        r = randomBigInt();
    } while (gcd(r, n) !== 1n);
    return r;
}

const ECKeys = generateKeypair();
const voterKeys = generateKeypair();

console.log("Election Commission Public Key:", ECKeys.publicKey);
console.log("Voter Public Key:", voterKeys.publicKey);

const candidates = ["Candidate 1", "Candidate 2"];
const numSets = 10;
const ballotSets = [];

for (let i = 0; i < numSets; i++) {
    const set = candidates.map(candidate => {
        const randomID = BigInt(randomInt(1e9, 1e10));
        const ballot = `${candidate}-${randomID}`;
        return {
            ballot,
            id: randomID
        };
    });
    ballotSets.push(set);
}

const blindedBallots = ballotSets.map(set => {
    return set.map(({ ballot }) => {
        const r = generateRandomR(ECKeys.publicKey.n);
        const { blindSignature, r: blindR } = generateBlindSignature(ballot, r, ECKeys.publicKey, ECKeys.privateKey);
        return { blindSignature, blindR, originalBallot: ballot };
    });
});


console.log("Blinded Ballots Sent to EC:", blindedBallots);

const selectedSetIndex = randomInt(0, numSets - 1);
const signedBallots = blindedBallots[selectedSetIndex].map(({ blindSignature, blindR, originalBallot }) => {

    const signedByEC = sign(stringToBigInt(originalBallot), ECKeys.privateKey);

    return {
        blindR,
        blindSignature,
        signedByEC,
        originalBallot
    };

    // // EC signs the blinded ballot
    // const signedBlindedBallot = sign(blindSignature, ECKeys.privateKey);

    // console.log("Signed Blinded Ballot by EC:", signedBlindedBallot);

    // // Voter unblinds the signature
    // const unblindedSignature = unblindSignature(signedBlindedBallot, blindR, ECKeys.publicKey);

    // return {
    //     unblindedSignature,
    //     originalBallot
    // };
});

// console.log("Signed Ballots Sent Back to Voter:", signedBallots);

const selectedBallot = signedBallots[0]; //candidate 1

console.log("Selected Ballot:", selectedBallot);

console.log("Selected Is Valid:", verify(selectedBallot.signedByEC, ECKeys.publicKey, stringToBigInt(selectedBallot.originalBallot)));

const encryptedBallot = encrypt(
    selectedBallot.signedByEC, // Encrypt the signed ballot, not the hash
    ECKeys.publicKey
);

console.log("Encrypted Ballot Sent to EC:", encryptedBallot);

const decryptedBallot = decrypt(encryptedBallot, ECKeys.privateKey);

console.log("Decrypted Ballot by EC:", decryptedBallot);

const isValid = verify(
    decryptedBallot,
    ECKeys.publicKey,
    stringToBigInt(selectedBallot.originalBallot)
);

console.log("Decrypted Ballot Verified by EC:", isValid);

const result = {
    candidate1Votes: 0,
    candidate2Votes: 0
};

if (isValid) {
    if (selectedBallot.originalBallot.includes("Candidate 1")) {
        result.candidate1Votes++;
    } else if (selectedBallot.originalBallot.includes("Candidate 2")) {
        result.candidate2Votes++;
    }
}

console.log("Final Tally:", result);