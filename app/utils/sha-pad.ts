import assert from "assert";

export const mergeUInt8Arrays = (
  a1: Uint8Array,
  a2: Uint8Array
): Uint8Array => {
  const merged = new Uint8Array(a1.length + a2.length);
  merged.set(a1, 0);
  merged.set(a2, a1.length);
  return merged;
};

export const int8toBytes = (num: number): Uint8Array => {
  const buf = new ArrayBuffer(1);
  new DataView(buf).setUint8(0, num);
  return new Uint8Array(buf);
};

// 64-bit big-endian length
export const int64toBytes = (num: number): Uint8Array => {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, BigInt(num), false);
  return new Uint8Array(buf);
};

/**
 * Standard SHA-256 MD-padding:
 * 1) append 0x80
 * 2) pad 0x00 until (len+8)≡0 mod 64
 * 3) append 8-byte BE length
 * 4) zero-extend with 8-byte words to maxShaBytes
 *
 * @param message    the input bytes
 * @param maxShaBytes  final total length in bytes
 * @returns [padded, length_before_extension]
 */
export function sha256Pad_circom(
  message: Uint8Array,
  maxShaBytes: number
): [Uint8Array, number] {
  const bitLen = message.length * 8;
  const lenBytes = int64toBytes(bitLen);

  // 1) append the 0x80
  let res = mergeUInt8Arrays(message, int8toBytes(0x80));

  // 2) pad 0x00 until (res.len*8 + 64) % 512 == 0
  while ((res.length * 8 + lenBytes.length * 8) % 512 !== 0) {
    res = mergeUInt8Arrays(res, int8toBytes(0));
  }

  // 3) append length
  res = mergeUInt8Arrays(res, lenBytes);
  assert((res.length * 8) % 512 === 0, "Padding did not complete properly!");
  const beforeExt = res.length;

  // 4) zero-extend to maxShaBytes with 8-byte zeros
  while (res.length < maxShaBytes) {
    res = mergeUInt8Arrays(res, int64toBytes(0));
  }
  assert(
    res.length === maxShaBytes,
    `Padded length ${res.length} != expected ${maxShaBytes}`
  );

  return [res, beforeExt];
}
