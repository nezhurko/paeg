function gcd(a: bigint, b: bigint) {
    while (b != 0n) {
        let t = b;
        b = a % b;
        a = t;
    }
    return a;
}

function bufferToBigInt(buffer: ArrayBuffer) {
    return BigInt('0x' + Buffer.from(buffer).toString('hex'));
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1n; // Divide by 2
        base = (base * base) % modulus;
    }
    return result;
}

function modInv(a: bigint, m: bigint) {
    let m0 = m;
    let y = BigInt(0);
    let x = BigInt(1);

    if (m === BigInt(1)) return BigInt(0);

    while (a > 1) {
        // q is quotient
        let q = a / m;
        let t = m;

        // m is remainder now, process same as Euclid's algo
        m = a % m;
        a = t;
        t = y;

        // Update y and x
        y = x - BigInt(q) * y;
        x = t;
    }

    // Make x positive
    if (x < 0) {
        x += m0;
    }

    return x;
}

function randomInt(min: number, max: number) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

export { gcd, bufferToBigInt, modPow, modInv, randomInt };