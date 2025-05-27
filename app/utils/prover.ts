import {
  AGE_CIRCUIT_ASSETS,
  AgeCircuitInput,
  DEFAULT_AGE_INPUT,
  JWT_CIRCUIT_ASSETS,
  JWTCircuitInput,
} from "./constant";
import * as snarkjs from "snarkjs";

const JWT_IPFS_GATEWAYS = [
  "https://cloudflare-ipfs.com/ipfs/",
  "https://gateway.pinata.cloud/ipfs/",
  "https://dweb.link/ipfs/",
  "https://trustless-gateway.link/ipfs/",
  "https://4everland.io/ipfs/",
  "https://w3s.link/ipfs/",
  "https://nftstorage.link/ipfs/",
];

export async function fetchBinary(path: string): Promise<ArrayBuffer> {
  // If path is NOT an IPFS hash, just fetch normally
  if (!path.startsWith("bafybei")) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(`Failed to fetch ${path}`);
    return await res.arrayBuffer();
  }

  // Otherwise, try fetching from multiple IPFS gateways
  for (const gateway of JWT_IPFS_GATEWAYS) {
    const url = `${gateway}${path}`;
    try {
      const res = await fetch(url);
      if (res.ok) {
        return await res.arrayBuffer();
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (err) {
      console.warn(`Fetch failed from ${url}, trying next...`);
    }
  }

  throw new Error(`Failed to fetch ${path} from all gateways`);
}

export class JwtProver {
  static async generateProof(input: JWTCircuitInput) {
    try {
      const wasm = new Uint8Array(await fetchBinary(JWT_CIRCUIT_ASSETS.WASM));
      const zkey = new Uint8Array(await fetchBinary(JWT_CIRCUIT_ASSETS.ZKEY));

      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        wasm,
        zkey
      );

      return { proof, publicSignals };
    } catch (error) {
      console.error("Error generating proof:", error);
      throw error;
    }
  }

  static async verifyProof(
    proof: snarkjs.Groth16Proof,
    publicSignals: string[]
  ): Promise<boolean> {
    try {
      const vkeyRes = await fetch(JWT_CIRCUIT_ASSETS.VKEY);
      const vkey = await vkeyRes.json();

      return await snarkjs.groth16.verify(vkey, publicSignals, proof);
    } catch (error) {
      console.error("Error verifying proof:", error);
      throw error;
    }
  }
}

export class AgeProver {
  static async generateProof(inputs: AgeCircuitInput) {
    try {
      const wasm = new Uint8Array(await fetchBinary(AGE_CIRCUIT_ASSETS.WASM));
      const zkey = new Uint8Array(await fetchBinary(AGE_CIRCUIT_ASSETS.ZKEY));

      console.log("default", DEFAULT_AGE_INPUT);
      console.log("inputs", inputs);

      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        inputs,
        wasm,
        zkey
      );

      return { proof, publicSignals };
    } catch (error) {
      console.error("Error generating proof:", error);
      throw error;
    }
  }

  static async verifyProof(
    proof: snarkjs.Groth16Proof,
    publicSignals: string[]
  ): Promise<boolean> {
    try {
      const vkeyRes = await fetch(AGE_CIRCUIT_ASSETS.VKEY);
      console.log("Fetching verification key from:", AGE_CIRCUIT_ASSETS.VKEY);
      const vkey = await vkeyRes.json();

      console.log("Verifying proof with vkey:", vkey);
      return await snarkjs.groth16.verify(vkey, publicSignals, proof);
    } catch (error) {
      console.error("Error verifying proof:", error);
      throw error;
    }
  }
}
