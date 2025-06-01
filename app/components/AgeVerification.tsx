"use client";

import { useState } from "react";
import { sha256 } from "@noble/hashes/sha256";
import { base64url } from "jose";
import { verifyJWT } from "../utils/utils";
import { AgeProver } from "../utils/prover";
import * as snarkjs from "snarkjs";
import { JwkEcdsaPublicKey } from "../utils/es256";
import { generateAgeInputs } from "../utils/generate_inputs";

export default function AgeVerifier() {
  const [token, setToken] = useState("");
  const [claimsInput, setClaimsInput] = useState("");
  const [jwk, setJwk] = useState<JwkEcdsaPublicKey>({
    kty: "EC",
    crv: "P-256",
    kid: "key-1",
    x: "dnQ2W9ZTsILYac3XdcvxrYNgIgjSkGJUMecMXVJk7XM",
    y: "0WhT_VgvnhNNj9aabTn4E4enR-iqbCrQtY9UWqD4XJY",
  });
  const [status, setStatus] = useState<string | null>(null);
  const [proof, setProof] = useState<snarkjs.Groth16Proof | null>(null);
  const [signals, setSignals] = useState<string[] | null>(null);
  const [currentStep, setCurrentStep] = useState(0);
  const [showProofDetails, setShowProofDetails] = useState(false);
  const [ageVerificationResult, setAgeVerificationResult] = useState<
    boolean | null
  >(null);
  const [showClaimsDetails, setShowClaimsDetails] = useState(false);

  const parsedClaims = claimsInput
    .split("\n")
    .map((claim) => claim.trim())
    .filter(Boolean)
    .map((claim, index) => {
      try {
        const decoded = atob(claim.replace(/-/g, "+").replace(/_/g, "/"));
        return { encoded: claim, decoded: decoded, index: index + 1 };
      } catch {
        return {
          encoded: claim,
          decoded: "Invalid encoding",
          index: index + 1,
        };
      }
    })
    .filter((claim) => {
      return claim.decoded.includes("roc_birthday");
    });

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
      let sd = payload?.vc?.credentialSubject?._sd;

      if (!Array.isArray(sd)) {
        setStatus("✅ Signature valid (no claims to check)");
        return;
      }

      const claims = claimsInput.trim().split(/\r?\n/);
      let hashed = claims.map((c) => base64url.encode(sha256(c)));
      sd = sd.sort();
      hashed = hashed.sort();

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
    setAgeVerificationResult(null);

    try {
      const claims = claimsInput
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

      const hashedClaims = claims.map((e) =>
        base64url.encode(sha256(e)).toString()
      );

      let inputs = await generateAgeInputs(token, jwk, hashedClaims);

      const { proof, publicSignals } = await AgeProver.generateProof(
        JSON.parse(
          JSON.stringify(inputs, (_, v) =>
            typeof v === "bigint" ? v.toString() : v
          )
        )
      );

      setProof(proof);
      setSignals(publicSignals);

      const isAgeAbove18 = publicSignals && publicSignals[0] === "1";
      setAgeVerificationResult(isAgeAbove18);

      setStatus("✅ Proof generated");
    } catch {
      setCurrentStep(2);
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
      if (ok) {
        const isAgeAbove18 = signals && signals[0] === "1";
        setAgeVerificationResult(isAgeAbove18);
        setStatus("✅ Proof valid");
      } else {
        setStatus("❌ Proof invalid");
        setAgeVerificationResult(null);
      }
    } catch {
      setStatus("❌ Verification error");
      setAgeVerificationResult(null);
    }
  };

  const loadTest = () => {
    let token_with_claims =
      "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9rZXlzIiwia2lkIjoia2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BvZHJaU3FNYkN5OU5kdTRVZ1VHeTNSTmtoSDQ3OWVMUHBiZkFoVlNOdTdCNG9KdlV3THp5eGlQNEp0NWs5Y3FxbUNoYW54QWF6VEd4Sk12R3hZREFwTmtYZURXNU1QWmdaUmtqUmdEMXlhaWc1S0NFZ0FhVmJnOHpydllqTVRpMUJ6cWREcFBwa2VTRm1Kd2llajlZTlkiLCJuYmYiOjE3NDgzNjY5NTMsImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticlRRV1BUSk10MkZ1MTZIODR5bXdiYkc5TEdOaW5XN1luajUzWkNBVzE2Z3JBaEJpd3Y1M0FuYnY3ODdodDZueGFLTUdHQWdZOVdqdEZ4WVozaGpHZE1kMVNodVFvU3ZOZVh4Y2o1SmNiazJ1WXRmR2J3aW9GU2laUVhmekg3Y3RoaSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI0OXJrcUxQb2JSRWdjcDZSSHpKNTJsNWdjQXpmSG9yZWVXbWtMTTdhQzJ3IiwieSI6IlQ2SFB5OWZnN1FOV2RvTWt2UFVOajBLeFgtUVIzeS14NUdKbmtnc2hzZnMifX0sImV4cCI6MjA2Mzg5OTc1MywidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4Il0sImNyZWRlbnRpYWxTdGF0dXMiOnsidHlwZSI6IlN0YXR1c0xpc3QyMDIxRW50cnkiLCJpZCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIzE5Iiwic3RhdHVzTGlzdEluZGV4IjoiMTkiLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL2RlbW9kcml2aW5nbGljZW5zZTIwMjUwNDI1MTQxOC9WMS9iNjUzYWQ0Yi0zYjNhLTQ2ZjktYmVjMi1kNjg3Y2U5YzMyMjIiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiLXUxU0NkeVdPdmtXTkxqWVUtZEdCLUNIOVFWTTRBaTJzS0p1aVluMFprbyIsIjlFM2JJRmM1Y0Y3VDZGNmowNUV5Y3NhUGxkbnRVNjJaT2JheC11VmJyQWMiLCJGbk40ME1mMGNwTWhrU0thYWFROUR2d1NEcndfbFB0SEdiS0NPNWtHWm1BIiwiV3B2Nm93b0NyMmY2X0ZpYnB4YXBHekVLY1gzYjMxcHNfaHBxRWZEMGJEMCIsIl9FUlltdkt6d1pjbzdQNzNoNE9McGczSzE3Y2t4TkFBZlpSeUFuYVdhYUEiLCJhMDVPSDFQUmF3cHF6OFM5TXlZbndTQnVtREYyZjU4QkJvZ1Fsc0tOVVBBIl0sIl9zZF9hbGciOiJzaGEtMjU2In19LCJub25jZSI6IktaQ0k3U1MzIiwianRpIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvY3JlZGVudGlhbC8zZmQwMTE4Yy0yZDc3LTQ4M2UtOTRjYS1iMDAzMjdmNTllNzAifQ.OqGYU5HVhUCaLfg4hK1DU0XM78WzVxEl24fNKT6vNI8jFzDilb-HGpWQ1mrGWGvi-KOI_YQQ_R9ZWpypK8y_iw~WyJmSGlPTE9ZRVFhZkF3MjBCZjRxZXpBIiwibmFtZSIsIumZs-etseeOsiJd~WyJLVXYxVF9BNXpvVDlJbXFURmUwdUxnIiwiaWRfbnVtYmVyIiwiQTIzNDU2Nzg5MCJd~WyJuTDVDa2VaV2paSG13UjcxV05lWlZ3Iiwicm9jX2JpcnRoZGF5IiwiMDU3MDYwNSJd~WyJvZFNweWFjaUNuZUJneld1VEFyM0pRIiwidHlwZSIsIuaZrumAmuWwj-Wei-i7iiJd~WyJJdFVGQUV2S0kybFJCV2MzU19LTjhnIiwiY29udHJvbG51bWJlciIsIjQwMTA0MDIwOTE0NDUiXQ~WyJROWEySWM3b1IxUjRFQ0VXX3RYaUlRIiwiZ0RhdGUiLCIxMDIwNzAxIl0~";

    let [, ...claims] = token_with_claims.split("~");
    claims = claims.map((c) => c.trim()).filter(Boolean);

    setToken(token_with_claims);
    setClaimsInput(claims.join("\n"));
    setStatus("✅ Loaded test vector");
  };

  return (
    <div className="space-y-6">
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            JWT Token
          </label>
          <textarea
            rows={4}
            value={token}
            onChange={(e) => {
              setToken(e.target.value);
              let [, ...claims] = e.target.value.split("~");
              claims = claims.map((c) => c.trim()).filter(Boolean);
              setClaimsInput(claims.join("\n"));
            }}
            className="w-full border rounded-lg p-3 font-mono focus:ring-2 focus:ring-indigo-500"
          />
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-sm font-medium text-gray-700">
              Age Claims ({parsedClaims.length} detected)
            </label>
            {claimsInput && parsedClaims.length > 0 && (
              <button
                onClick={() => setShowClaimsDetails(!showClaimsDetails)}
                className="text-sm text-indigo-600 hover:text-indigo-800 font-medium"
              >
                {showClaimsDetails ? "Hide Details" : "Show Details"}
              </button>
            )}
          </div>

          {claimsInput ? (
            <div className="border rounded-lg bg-gray-50">
              <div className="p-3 border-b bg-gray-100 rounded-t-lg">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-gray-700">
                    Age Claims from JWT (roc_birthday)
                  </span>
                  {parsedClaims.length > 0 ? (
                    <span className="px-2 py-1 text-xs bg-green-100 text-green-800 rounded-full">
                      {parsedClaims.length} age claim
                      {parsedClaims.length !== 1 ? "s" : ""}
                    </span>
                  ) : (
                    <span className="px-2 py-1 text-xs bg-orange-100 text-orange-800 rounded-full">
                      No age claims found
                    </span>
                  )}
                </div>
              </div>

              {parsedClaims.length > 0 ? (
                <>
                  {showClaimsDetails ? (
                    <div className="p-4 space-y-3">
                      {parsedClaims.map((claim, index) => (
                        <div
                          key={index}
                          className="border-l-4 border-indigo-200 pl-4"
                        >
                          <div className="text-sm text-gray-600 mb-1">
                            Age Claim #{claim.index}
                          </div>
                          <div className="font-mono text-xs text-gray-800 bg-white p-2 rounded border">
                            <div className="mb-2">
                              <span className="text-gray-500">Encoded:</span>
                              <div className="break-all">{claim.encoded}</div>
                            </div>
                            <div>
                              <span className="text-gray-500">
                                Decoded (Age Info):
                              </span>
                              <div className="text-indigo-600 font-medium">
                                {claim.decoded}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4">
                      <div className="text-sm text-gray-600 mb-2">
                        Age claims detected and ready for verification
                      </div>
                      <div className="space-y-2">
                        {parsedClaims.map((claim, index) => (
                          <div
                            key={index}
                            className="bg-white p-3 rounded border border-indigo-200"
                          >
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-xs text-gray-500">
                                Age Claim #{claim.index}:
                              </span>
                              <span className="px-2 py-1 text-xs bg-indigo-100 text-indigo-800 rounded">
                                roc_birthday
                              </span>
                            </div>
                            <div className="text-sm text-indigo-600 font-medium font-mono">
                              {claim.decoded}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="p-4 text-center text-gray-500">
                  <div className="text-sm mb-2">
                    No age claims (roc_birthday) found in the JWT token
                  </div>
                  <div className="text-xs text-gray-400">
                    Age verification requires claims containing birth date
                    information
                  </div>
                </div>
              )}

              <div className="p-3 border-t bg-gray-50">
                <div className="text-xs text-gray-500 mb-2">
                  All Claims (for verification):
                </div>
                <textarea
                  rows={3}
                  value={claimsInput}
                  onChange={(e) => setClaimsInput(e.target.value)}
                  placeholder="Claims will auto-populate when you enter a JWT token above..."
                  className="w-full border rounded p-2 text-sm font-mono focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            </div>
          ) : (
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center">
              <div className="text-gray-500 mb-2">
                Age claims will auto-populate when you enter a JWT token
              </div>
              <textarea
                rows={3}
                value={claimsInput}
                onChange={(e) => setClaimsInput(e.target.value)}
                placeholder="Or manually enter claims here (one per line, base64 encoded)..."
                className="w-full border rounded p-2 text-sm font-mono focus:ring-2 focus:ring-indigo-500"
              />
            </div>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            JWK Public Key (JSON format)
          </label>
          <textarea
            rows={6}
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
        </div>
      </div>

      <div className="border-t pt-6">
        <h2 className="text-2xl font-bold mb-4 text-gray-800">
          Age Verification Actions
        </h2>

        <div className="w-full mb-4">
          <div className="flex justify-between mb-1 text-sm text-gray-600 font-medium">
            <span>Step {currentStep} of 4</span>
            <span>
              {currentStep === 1 && "Loaded"}
              {currentStep === 2 && "Validated"}
              {currentStep === 3 && "Proof Generated"}
              {currentStep === 4 && "Verified"}
              {currentStep === 0 && "Idle"}
            </span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div
              className="bg-indigo-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${(currentStep / 4) * 100}%` }}
            />
          </div>
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => {
              loadTest();
              setCurrentStep(1);
            }}
            className="px-5 py-2 bg-gray-200 rounded-lg hover:bg-gray-300 transition-colors"
          >
            1. Load Test
          </button>

          <button
            onClick={async () => {
              await handleValidate();
              setCurrentStep(2);
            }}
            className="px-5 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
          >
            2. Validate JWT
          </button>

          <button
            onClick={async () => {
              await handleGenerate();
              setCurrentStep(3);
            }}
            className="px-5 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            3. Generate Proof
          </button>

          <button
            onClick={async () => {
              await handleVerify();
              setCurrentStep(4);
            }}
            className="px-5 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
          >
            4. Verify Proof
          </button>

          <button
            onClick={() => {
              setToken("");
              setClaimsInput("");
              setJwk({
                kty: "EC",
                crv: "P-256",
                x: "rJUIrWnliWn5brtxVJPlGNZl2hKTosVMlWDc-G-gScM",
                y: "mm3p9quG010NysYgK-CAQz2E-wTVSNeIHl_HvWaaM6I",
              });
              setStatus(null);
              setProof(null);
              setSignals(null);
              setShowProofDetails(false);
              setAgeVerificationResult(null);
              setCurrentStep(0);
            }}
            className="px-5 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
          >
            5. Reset
          </button>
        </div>
      </div>

      {status && (
        <p
          className={`text-lg font-medium ${
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

      {ageVerificationResult !== null && currentStep === 4 && (
        <div
          className={`p-4 rounded-lg border-2 ${
            ageVerificationResult
              ? "bg-green-50 border-green-200 text-green-800"
              : "bg-red-50 border-red-200 text-red-800"
          }`}
        >
          <div className="flex items-center gap-2">
            <span className="text-2xl">
              {ageVerificationResult ? "✅" : "❌"}
            </span>
            <span className="text-xl font-semibold">
              Age Verification:{" "}
              {ageVerificationResult ? "Above 18" : "Below 18"}
            </span>
          </div>
          <p className="mt-2 text-sm">
            The zero-knowledge proof{" "}
            {ageVerificationResult ? "confirms" : "indicates"} that the person
            is{" "}
            {ageVerificationResult ? "18 years or older" : "under 18 years old"}
            .
          </p>
        </div>
      )}

      {(proof || signals) && (
        <div className="border rounded-lg p-4 bg-gray-50">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-medium text-gray-800">Proof Details</h2>
            <button
              onClick={() => setShowProofDetails(!showProofDetails)}
              className="px-3 py-1 text-sm bg-gray-200 hover:bg-gray-300 rounded-md transition-colors"
            >
              {showProofDetails ? "Hide Details" : "View Details"}
            </button>
          </div>

          {showProofDetails && (
            <div className="mt-4 space-y-4">
              {proof && (
                <section>
                  <h3 className="text-lg font-medium text-gray-700 mb-2">
                    Zero-Knowledge Proof
                  </h3>
                  <pre className="bg-white p-4 rounded-lg overflow-auto text-sm border">
                    {JSON.stringify(proof, null, 2)}
                  </pre>
                </section>
              )}

              {signals && (
                <section>
                  <h3 className="text-lg font-medium text-gray-700 mb-2">
                    Public Signals
                  </h3>
                  <pre className="bg-white p-4 rounded-lg overflow-auto text-sm border">
                    {JSON.stringify(signals, null, 2)}
                  </pre>
                  <p className="text-sm text-gray-600 mt-2">
                    Signal value: {signals[0]} (1 = Above 18, 0 = Below 18)
                  </p>
                </section>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
