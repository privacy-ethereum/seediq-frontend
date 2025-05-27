import { useState } from "react";
import { sha256 } from "@noble/hashes/sha256";
import { base64url } from "jose";
import { verifyJWT } from "../utils/utils";
import { JwtProver } from "../utils/prover";
import * as snarkjs from "snarkjs";
import { generateJWTInputs } from "../utils/generate_inputs";
import { JwkEcdsaPublicKey } from "../utils/es256";

export default function JWTVerifier() {
  const [token, setToken] = useState("");
  const [claimsInput, setClaimsInput] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [proof, setProof] = useState<snarkjs.Groth16Proof | null>(null);
  const [signals, setSignals] = useState<string[] | null>(null);

  const [jwk, setJwk] = useState<JwkEcdsaPublicKey>({
    kty: "EC",
    crv: "P-256",
    x: "rJUIrWnliWn5brtxVJPlGNZl2hKTosVMlWDc-G-gScM",
    y: "mm3p9quG010NysYgK-CAQz2E-wTVSNeIHl_HvWaaM6I",
  });

  const handleValidate = async () => {
    try {
      if (token === "") return setStatus("❌ Missing JWT Token");
      if (claimsInput === "") return setStatus("❌ Missing Claims");

      const isValid = await verifyJWT(token, jwk);
      if (!isValid) return setStatus("❌ Signature Invalid");

      const payload = JSON.parse(atob(token.split(".")[1]));
      const sd = payload?.vc?.credentialSubject?._sd;
      if (!sd || !Array.isArray(sd))
        return setStatus("✅ Valid Signature (no hashed claims)");

      const claims = claimsInput
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

      const hashedClaims = claims.map((e) =>
        base64url.encode(sha256(e)).toString()
      );

      for (let i = 0; i < sd.length; i++) {
        if (sd[i] !== hashedClaims[i]) {
          return setStatus(`❌ Claim ${i + 1} hash mismatch`);
        }
      }

      setStatus("✅ Valid Signature + Claims Match");
    } catch (err) {
      if (err instanceof Error) {
        setStatus(`❌ Error: ${err.message}`);
      } else {
        setStatus("❌ An unknown error occurred");
      }
    }
  };

  const handleGenerateProof = async () => {
    try {
      setStatus("⏳ Generating proof...");
      const claims = claimsInput.split("\n").map((s) => s.trim());
      const hashedClaims = claims.map((e) =>
        base64url.encode(sha256(e)).toString()
      );

      const inputs = generateJWTInputs(token, jwk, hashedClaims);
      const input = JSON.parse(
        JSON.stringify(
          inputs,
          (_, v) => (typeof v === "bigint" ? v.toString() : v),
          2
        )
      );
      const { proof, publicSignals } = await JwtProver.generateProof(input);

      setProof(proof);
      setSignals(publicSignals);
      setStatus("✅ Proof generated successfully");
    } catch (err) {
      console.error(err);
      setStatus("❌ Failed to generate proof");
    }
  };

  const handleVerifyProof = async () => {
    try {
      if (!proof || !signals) {
        return setStatus("❌ No proof or signals to verify");
      }

      setStatus("⏳ Verifying proof...");
      const isValid = await JwtProver.verifyProof(proof, signals);
      setStatus(
        isValid
          ? "✅ Proof verification succeeded"
          : "❌ Proof verification failed"
      );
    } catch (err) {
      console.error(err);
      setStatus("❌ Error during verification");
    }
  };

  return (
    <main>
      <div className="max-w-3xl mx-auto bg-white shadow p-6 rounded-xl space-y-6">
        <textarea
          placeholder="JWT Token"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          className="w-full border p-2 rounded"
          rows={4}
        />

        <textarea
          placeholder="Raw Claims (one per line)"
          value={claimsInput}
          onChange={(e) => setClaimsInput(e.target.value)}
          className="w-full border p-2 rounded"
          rows={3}
        />

        <textarea
          placeholder="JWK"
          value={JSON.stringify(jwk, null, 2)}
          onChange={(e) => {
            try {
              setJwk(JSON.parse(e.target.value));
            } catch {
              setStatus("❌ Invalid JWK JSON");
            }
          }}
          className="w-full border p-2 font-mono rounded"
          rows={6}
        />

        <div className="space-x-4">
          <button
            onClick={() => {
              setToken(
                "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkva2V5cyIsImtpZCI6ImtleS0xIiwidHlwIjoidmMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJkaWQ6a2V5OnpZcU52VkNrWVhhTXNGVVhEemJvRk1DMXRSV0ZjOHBUTGRONTgzb3FhcG9LNk1veno5dEVWVWpYU2lDN3Y2eXlOR0I4TW5DZUh1SE5hWlpzczFYS1E5dktzY2EyN0VIM0NQTXFSSnN5b2pqdXRyNEtrMzJaWVE0TDRjdHpZaDVHMWhrR1I3VFlhQ0Q3ekczWU1WS0V2dWQxejhZVnR5N2lxZzhBVTZxQ3hvS25ibkVVNnJEQSIsIm5iZiI6MTczOTgxNjY3MiwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JzWTlEUnFTQ2d6elJ1RmJwcTlxd0pUTGtCbm1tQlhoZFNkcTZCREpSTXg2dENHMWp0a2R3Z0tYTmZOMXFXRVJEdnhhYzVyWTZoY25GUDdIdjYzaU01eTNWeHRNTjRUc3h5WnZibnJhcFcyUnBGb3ZFMURKNG03ZURWTFN1cUd0YzFpIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlBrcV82ZDJpeUIwZGVvalYyLXlta0ZWeUpNeElfTDlHZVF4aDBORExoNDQ9IiwieSI6IjBOZnFMdmUtSXEwSFZZUE11eEctWHpRNUlmNktaOFhvQ0hkNmZOaDhsZFU9In19LCJleHAiOjY3OTc3NzcxODcyLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiOTM1ODE5MjVfZGQiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMtdWF0LndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzkzNTgxOTI1X2RkL3IwIzYiLCJzdGF0dXNMaXN0SW5kZXgiOiI2Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvOTM1ODE5MjVfZGQvcjAiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9mcm9udGVuZC11YXQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzkzNTgxOTI1L2RkL1YxL2Q0ZDFhMGY5LTNmMDktNGMyZS1iODk5LTA4YzM0NDkwYzhlYSIsInR5cGUiOiJKc29uU2NoZW1hIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJKY2lHYzViS2lkT0dteGp1dkM4TGRVeWthVlhCWEJQaEJYMWtYcERlLUxvIiwicFZPdzJOajU3RzJOa2VWSEJDV3doRUJqdWZTSmhwOWxwM201VzltQWg5QSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9fSwibm9uY2UiOiJCSElDVTI2TiIsImp0aSI6Imh0dHBzOi8vaXNzdWVyLXZjLXVhdC53YWxsZXQuZ292LnR3L2FwaS9jcmVkZW50aWFsLzRmYzNiYTY1LTY1ZGQtNDEyNC05ZTczLWNhOWY0OWNkNzc2NyJ9.h0wBjwjBDb48wZ_XVWnnrRrWh2Sgd4Lq7sc72N54svJFklnFuHebxvn-Ui6jftnQbPnLTKEyJbE75DatCkfkdQ"
              );
              setClaimsInput(
                `WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ\nWyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd`
              );
              setStatus("✅ Loaded test vector");
            }}
            className="bg-purple-600 text-white px-6 py-2 rounded hover:bg-purple-700"
          >
            Use Test Vector
          </button>

          <button
            onClick={handleValidate}
            className="bg-black text-white px-6 py-2 rounded hover:bg-gray-800"
          >
            Validate JWT
          </button>

          <button
            onClick={handleGenerateProof}
            className="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700"
          >
            Generate Proof
          </button>

          <button
            onClick={handleVerifyProof}
            className="bg-green-600 text-white px-6 py-2 rounded hover:bg-green-700"
          >
            Verify Proof
          </button>
        </div>

        {status && (
          <p
            className={`text-lg mt-4 ${
              status.startsWith("✅")
                ? "text-green-600"
                : status.startsWith("⏳")
                ? "text-yellow-600"
                : "text-red-600"
            }`}
          >
            {status}
          </p>
        )}

        {proof && (
          <div className="mt-6">
            <h2 className="text-lg font-semibold">Proof</h2>
            <pre className="text-sm bg-gray-100 p-4 rounded overflow-auto max-h-64">
              {JSON.stringify(proof, null, 2)}
            </pre>
          </div>
        )}

        {signals && (
          <div className="mt-6">
            <h2 className="text-lg font-semibold">Public Signals</h2>
            <pre className="text-sm bg-gray-100 p-4 rounded overflow-auto max-h-64">
              {JSON.stringify(signals, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </main>
  );
}
