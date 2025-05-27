"use client";

import { useState } from "react";
import { Github } from "lucide-react";
import AgeVerifier from "./components/AgeVerification";
import JWTVerifier from "./components/JwtVerification";

export default function Home() {
  const [view, setView] = useState<"age" | "jwt">("age");

  return (
    <main className="min-h-screen bg-gray-50 py-10 px-4">
      <div className="max-w-3xl mx-auto">
        <div className="bg-white shadow-md rounded-2xl overflow-hidden">
          <div className="bg-indigo-600 p-6 flex flex-col sm:flex-row sm:items-center sm:justify-between">
            <h1 className="text-2xl font-semibold text-white mb-4 sm:mb-0">
              Seediq {view === "age" ? "zk-Age Validator" : "JWT Verifier"}
            </h1>
            <div className="flex items-center space-x-6">
              <div className="inline-flex bg-white rounded-full p-1">
                <button
                  onClick={() => setView("age")}
                  className={`px-4 py-2 rounded-full text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-indigo-500 ${
                    view === "age"
                      ? "bg-indigo-600 text-white"
                      : "text-indigo-600 hover:bg-indigo-100"
                  }`}
                >
                  Age Verifier
                </button>
                <button
                  onClick={() => setView("jwt")}
                  className={`px-4 py-2 rounded-full text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-indigo-500 ${
                    view === "jwt"
                      ? "bg-indigo-600 text-white"
                      : "text-indigo-600 hover:bg-indigo-100"
                  }`}
                >
                  JWT Verifier
                </button>
              </div>
              <a
                href="https://github.com/adria0/seediq-playground"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center text-white hover:text-gray-200 focus:outline-none focus:ring-2 focus:ring-white rounded"
              >
                <Github className="w-6 h-6 mr-2" />
                GitHub
              </a>
            </div>
          </div>

          <div className="p-6">
            {view === "age" ? <AgeVerifier /> : <JWTVerifier />}
          </div>
        </div>
      </div>
    </main>
  );
}
