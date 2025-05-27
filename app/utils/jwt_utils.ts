import { toByteArray } from "base64-js";
import { BerReader } from "asn1";
import { sha256Pad_circom } from "./sha-pad";

// Convert a string to an array of BigInts
export function stringToPaddedBigIntArray(
  s: string,
  padLength: number
): bigint[] {
  let values = Array.from(s).map((char) => BigInt(char.charCodeAt(0)));
  while (values.length < padLength) {
    values.push(0n);
  }
  return values;
}

// Convert a string to an array of BigInts with k limbs of n bits
export function bigintToLimbs(x: bigint, n: number, k: number): bigint[] {
  let mod: bigint = 1n;
  for (let idx = 0; idx < n; idx++) {
    mod = mod * 2n;
  }

  let ret: bigint[] = [];
  let x_temp: bigint = x;
  for (let idx = 0; idx < k; idx++) {
    ret.push(x_temp % mod);
    x_temp = x_temp / mod;
  }
  return ret;
}

// Convert a buffer to a BigInt
export function bufferToBigInt(buffer: Buffer) {
  // Convert the buffer to a hexadecimal string then to BigInt.
  return BigInt("0x" + buffer.toString("hex"));
}

// Convert a base64 string to a BigInt
export function base64ToBigInt(base64Str: string) {
  const buffer = Buffer.from(base64Str, "base64");
  const hex = buffer.toString("hex");
  return BigInt("0x" + hex);
}

export function uint8ArrayToBigIntArray(msg: Uint8Array): bigint[] {
  let mpb = [];
  for (const b of msg) {
    mpb.push(BigInt(b));
  }
  return mpb;
}

// Get the x and y coordinates from a PEM public key
// Note that this function is very naive and does not check for OIDs
export function extractXYFromPEM(pk: string) {
  const pk1 = toByteArray(pk);
  const reader = new BerReader(Buffer.from(pk1));
  reader.readSequence();
  reader.readSequence();
  reader.readOID();
  reader.readOID();

  const buffer = reader.readString(3, true)!;

  const xy = buffer.subarray(2);
  const x = xy.subarray(0, 32);
  const y = xy.subarray(32);

  return [bufferToBigInt(x), bufferToBigInt(y)];
}
export async function encodeClaims(
  claims: string[],
  maxClaims: number,
  maxClaimsLength: number
): Promise<{ claimArray: bigint[][]; claimLengths: bigint[] }> {
  const claimArray = Array(maxClaims)
    .fill(null)
    .map(() => Array(maxClaimsLength).fill(0n));
  const claimLengths = Array(maxClaims).fill(0n);

  for (let i = 0; i < claims.length && i < maxClaims; i++) {
    const claim = claims[i];
    const utf8Bytes = Uint8Array.from(Buffer.from(claim, "utf8"));
    const [paddedBytes] = await sha256Pad_circom(utf8Bytes, maxClaimsLength);

    for (let j = 0; j < paddedBytes.length && j < maxClaimsLength; j++) {
      claimArray[i][j] = BigInt(paddedBytes[j]);
    }

    claimLengths[i] = BigInt(claim.length);
  }

  return { claimArray, claimLengths };
}
