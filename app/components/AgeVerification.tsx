"use client";

import { useState } from "react";
import { sha256 } from "@noble/hashes/sha256";
import { base64url } from "jose";
import { verifyJWT } from "../utils/utils";
import { AgeProver, fetchBinary } from "../utils/prover";
import * as snarkjs from "snarkjs";

import { JwkEcdsaPublicKey } from "../utils/es256";
import { generateAgeInputs } from "../utils/generate_inputs";
import { AGE_CIRCUIT_ASSETS } from "../utils/constant";

export default function AgeVerifier() {
  const [token, setToken] = useState("");
  const [claimsInput, setClaimsInput] = useState("");
  const [jwk, setJwk] = useState<JwkEcdsaPublicKey>({
    kty: "EC",
    crv: "P-256",
    x: "rJUIrWnliWn5brtxVJPlGNZl2hKTosVMlWDc-G-gScM",
    y: "mm3p9quG010NysYgK-CAQz2E-wTVSNeIHl_HvWaaM6I",
  });
  const [status, setStatus] = useState<string | null>(null);
  const [proof, setProof] = useState<snarkjs.Groth16Proof | null>(null);
  const [signals, setSignals] = useState<string[] | null>(null);

  const handleValidate = async () => {
    if (!token || !claimsInput) {
      setStatus("❌ Please provide both JWT and claims");
      return;
    }
    setStatus("⏳ Validating...");
    try {
      let token_Without_claims = token.split("~")[0];
      const validSig = await verifyJWT(token_Without_claims, jwk);
      if (!validSig) throw new Error("Invalid signature");

      const payload = JSON.parse(atob(token_Without_claims.split(".")[1]));
      const sd = payload?.vc?.credentialSubject?._sd;
      if (!Array.isArray(sd)) {
        setStatus("✅ Signature valid (no claims to check)");
        return;
      }

      const claims = claimsInput.trim().split(/\r?\n/);

      // decode the age claim 2
      const ageClaim = atob(claims[1]);
      const roc_birthday = ageClaim.split(",")[1];

      if (roc_birthday === "roc_birthday") {
        setStatus("❌ Invalid ROC birthday claim format");
        return;
      }

      const hashed = claims.map((c) => base64url.encode(sha256(c)));
      for (let i = 0; i < sd.length; i++) {
        if (sd[i] !== hashed[i]) {
          setStatus(`❌ Claim #${i + 1} mismatch`);
          return;
        }
      }
      setStatus("✅ Signature and Age Claim match Successfully");
    } catch (err) {
      setStatus(`❌ ${err instanceof Error ? err.message : "Error"}`);
    }
  };

  const handleGenerate = async () => {
    setStatus("⏳ Generating proof...");
    try {
      const claims = claimsInput
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

      const hashedClaims = claims.map((e) =>
        base64url.encode(sha256(e)).toString()
      );

      const inputs = await generateAgeInputs(token, jwk, hashedClaims);
      const wasm = new Uint8Array(await fetchBinary(AGE_CIRCUIT_ASSETS.WASM));
      const zkey = new Uint8Array(await fetchBinary(AGE_CIRCUIT_ASSETS.ZKEY));

      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        JSON.parse(
          JSON.stringify(inputs, (_, v) =>
            typeof v === "bigint" ? v.toString() : v
          )
        ),
        wasm,
        zkey
      );

      setProof(proof);
      setSignals(publicSignals);
      setStatus("✅ Proof generated");
    } catch {
      setStatus("❌ Proof generation failed");
    }
  };

  const handleVerify = async () => {
    if (!proof || !signals) {
      setStatus("❌ No proof/signals");
      return;
    }
    setStatus("⏳ Verifying proof...");
    try {
      const ok = await AgeProver.verifyProof(proof, signals);
      setStatus(ok ? "✅ Proof valid" : "❌ Proof invalid");
    } catch {
      setStatus("❌ Verification error");
    }
  };

  const loadTest = () => {
    setToken(
      "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkva2V5cyIsImtpZCI6ImtleS0xIiwidHlwIjoidmMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJkaWQ6a2V5OnpZcU52VkNrWVhhTXNGVVhEemJvRk1DMXRSV0ZjOHBUTGRONTgzb3FhcG9LNk1veno5dEVWVWpYU2lDN3Y2eXlOR0I4TW5DZUh1SE5hWlpzczFYS1E5dktzY2EyN0VIM0NQTXFSSnN5b2pqdXRyNEtrMzJaWVE0TDRjdHpZaDVHMWhrR1I3VFlhQ0Q3ekczWU1WS0V2dWQxejhZVnR5N2lxZzhBVTZxQ3hvS25ibkVVNnJEQSIsIm5iZiI6MTczOTgxNjY3MiwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JzWTlEUnFTQ2d6elJ1RmJwcTlxd0pUTGtCbm1tQlhoZFNkcTZCREpSTXg2dENHMWp0a2R3Z0tYTmZOMXFXRVJEdnhhYzVyWTZoY25GUDdIdjYzaU01eTNWeHRNTjRUc3h5WnZibnJhcFcyUnBGb3ZFMURKNG03ZURWTFN1cUd0YzFpIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlBrcV82ZDJpeUIwZGVvalYyLXlta0ZWeUpNeElfTDlHZVF4aDBORExoNDQ9IiwieSI6IjBOZnFMdmUtSXEwSFZZUE11eEctWHpRNUlmNktaOFhvQ0hkNmZOaDhsZFU9In19LCJleHAiOjY3OTc3NzcxODcyLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiOTM1ODE5MjVfZGQiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMtdWF0LndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzkzNTgxOTI1X2RkL3IwIzYiLCJzdGF0dXNMaXN0SW5kZXgiOiI2Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvOTM1ODE5MjVfZGQvcjAiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9mcm9udGVuZC11YXQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzkzNTgxOTI1L2RkL1YxL2Q0ZDFhMGY5LTNmMDktNGMyZS1iODk5LTA4YzM0NDkwYzhlYSIsInR5cGUiOiJKc29uU2NoZW1hIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJKY2lHYzViS2lkT0dteGp1dkM4TGRVeWthVlhCWEJQaEJYMWtYcERlLUxvIiwicFZPdzJOajU3RzJOa2VWSEJDV3doRUJqdWZTSmhwOWxwM201VzltQWg5QSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9fSwibm9uY2UiOiJCSElDVTI2TiIsImp0aSI6Imh0dHBzOi8vaXNzdWVyLXZjLXVhdC53YWxsZXQuZ292LnR3L2FwaS9jcmVkZW50aWFsLzRmYzNiYTY1LTY1ZGQtNDEyNC05ZTczLWNhOWY0OWNkNzc2NyJ9.h0wBjwjBDb48wZ_XVWnnrRrWh2Sgd4Lq7sc72N54svJFklnFuHebxvn-Ui6jftnQbPnLTKEyJbE75DatCkfkdQ~WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ~WyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd"
    );
    setClaimsInput(
      `WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ\nWyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd`
    );
    setStatus("✅ Loaded test vector");
  };

  return (
    <div className="space-y-6">
      <textarea
        rows={4}
        placeholder="Paste JWT token here"
        value={token}
        onChange={(e) => setToken(e.target.value)}
        className="w-full border rounded-lg p-3 font-mono focus:ring-2 focus:ring-indigo-500"
      />

      <textarea
        rows={3}
        placeholder="Claims (one per line)"
        value={claimsInput}
        onChange={(e) => setClaimsInput(e.target.value)}
        className="w-full border rounded-lg p-3 focus:ring-2 focus:ring-indigo-500"
      />

      <textarea
        rows={6}
        placeholder="JWK JSON"
        value={JSON.stringify(jwk, null, 2)}
        onChange={(e) => {
          try {
            setJwk(JSON.parse(e.target.value));
          } catch {
            setStatus("❌ Invalid JWK");
          }
        }}
        className="w-full border rounded-lg p-3 font-mono focus:ring-2 focus:ring-indigo-500"
      />

      <div className="flex flex-wrap gap-3">
        <button
          onClick={loadTest}
          className="px-5 py-2 bg-gray-200 rounded-lg hover:bg-gray-300"
        >
          Load Test
        </button>
        <button
          onClick={handleValidate}
          className="px-5 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
        >
          Validate JWT
        </button>
        <button
          onClick={handleGenerate}
          className="px-5 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          Generate Proof
        </button>
        <button
          onClick={handleVerify}
          className="px-5 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
        >
          Verify Proof
        </button>
      </div>

      {status && (
        <p
          className={`text-lg ${
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
        <section>
          <h2 className="text-xl font-medium">Proof</h2>
          <pre className="bg-gray-100 p-4 rounded-lg overflow-auto">
            {JSON.stringify(proof, null, 2)}
          </pre>
        </section>
      )}

      {signals && (
        <section>
          <h2 className="text-xl font-medium">Public Signals</h2>
          <pre className="bg-gray-100 p-4 rounded-lg overflow-auto">
            {JSON.stringify(signals, null, 2)}
          </pre>
        </section>
      )}
    </div>
  );
}
