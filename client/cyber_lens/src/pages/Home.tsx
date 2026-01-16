import React, { useState } from "react";
import { httpJson } from "../utils/httpClient";

interface LookupResponse {
  ioc: string;
  type: string;
  score: number;
  verdict: string;
  providers: unknown[];
  meta: unknown;
}

const Home: React.FC = () => {
  const [iocValue, setIocValue] = useState("");
  const [iocType, setIocType] = useState("IP");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<LookupResponse | null>(null);

  const handleSearch = async () => {
    if (!iocValue.trim()) {
      setError("Please enter a valid IOC");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await httpJson<LookupResponse>("/lookup", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ioc: iocValue.trim(),
          type: iocType,
        }),
      });

      setResult(response);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "An error occurred during lookup"
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100">
      {/* HERO */}
      <section className="relative overflow-hidden">
        {/* Subtle background grid */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_1px_1px,#262626_1px,transparent_0)] bg-[size:24px_24px] opacity-20" />

        <div className="relative max-w-6xl mx-auto px-4 pt-28 pb-32 text-center">
          <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight mb-6">
            <span>Cyber</span>&nbsp;
            <span className="text-cyan-400">Lens</span>
          </h1>

          <p className="max-w-2xl mx-auto text-lg sm:text-xl text-neutral-400 mb-14">
            A focused threat intelligence platform for fast IOC inspection,
            contextual verdicts, and analyst-driven decisions.
          </p>

          {/* SEARCH PANEL */}
          <div className="max-w-2xl mx-auto border border-neutral-800 bg-neutral-900">
            <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 p-4">
              <input
                type="text"
                placeholder="Enter IP, domain, URL, or hash"
                value={iocValue}
                onChange={(e) => setIocValue(e.target.value)}
                className="sm:col-span-3 px-4 py-3 bg-neutral-950 border border-neutral-800 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />

              <select
                value={iocType}
                onChange={(e) => setIocType(e.target.value)}
                className="sm:col-span-1 px-3 py-3 bg-neutral-950 border border-neutral-800 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <option value="IP">IP</option>
                <option value="Domain">Domain</option>
                <option value="URL">URL</option>
                <option value="Hash">Hash</option>
              </select>

              <button
                onClick={handleSearch}
                disabled={loading}
                className="sm:col-span-1 px-4 py-3 bg-cyan-500 text-neutral-950 font-semibold hover:bg-cyan-400 transition-colors disabled:bg-neutral-700 disabled:cursor-not-allowed"
              >
                {loading ? "Analyzing..." : "Analyze"}
              </button>
            </div>

            {/* Error Message */}
            {error && (
              <div className="mt-4 p-4 bg-red-900/20 border border-red-800 text-red-400 text-sm">
                <strong>Error:</strong> {error}
              </div>
            )}

            {/* Results Display */}
            {result && (
              <div className="mt-4 p-6 bg-neutral-950 border border-neutral-800 text-left">
                <h3 className="text-xl font-semibold mb-4 text-cyan-400">
                  Analysis Results
                </h3>

                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div className="text-neutral-500">IOC:</div>
                    <div className="font-mono text-neutral-200 break-all">
                      {result.ioc}
                    </div>

                    <div className="text-neutral-500">Detected Type:</div>
                    <div className="font-semibold text-cyan-400">
                      {result.type}
                    </div>

                    <div className="text-neutral-500">Threat Score:</div>
                    <div className="font-bold text-lg">
                      <span
                        className={
                          result.score >= 70
                            ? "text-red-500"
                            : result.score >= 40
                            ? "text-yellow-500"
                            : "text-green-500"
                        }
                      >
                        {result.score}
                      </span>
                      <span className="text-neutral-500 text-sm ml-1">
                        / 100
                      </span>
                    </div>

                    <div className="text-neutral-500">Verdict:</div>
                    <div className="font-semibold">
                      <span
                        className={
                          result.verdict === "malicious"
                            ? "text-red-500"
                            : result.verdict === "suspicious"
                            ? "text-yellow-500"
                            : "text-green-500"
                        }
                      >
                        {result.verdict.toUpperCase()}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* FEATURES */}
      <section className="border-t border-neutral-800 py-24 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl sm:text-4xl font-semibold mb-14 text-center">
            Built for real security work
          </h2>

          <div className="grid gap-6 md:grid-cols-3">
            <div className="border border-neutral-800 bg-neutral-900 p-6">
              <h3 className="text-lg font-semibold mb-3 text-cyan-400">
                IOC-Centric Analysis
              </h3>
              <p className="text-sm text-neutral-400 leading-relaxed">
                Inspect IPs, domains, URLs, and hashes with contextual metadata
                and historical signals.
              </p>
            </div>

            <div className="border border-neutral-800 bg-neutral-900 p-6">
              <h3 className="text-lg font-semibold mb-3 text-cyan-400">
                Clear Verdict System
              </h3>
              <p className="text-sm text-neutral-400 leading-relaxed">
                Immediate classification — malicious, suspicious, or clean —
                optimized for fast triage.
              </p>
            </div>

            <div className="border border-neutral-800 bg-neutral-900 p-6">
              <h3 className="text-lg font-semibold mb-3 text-cyan-400">
                Analyst-First UI
              </h3>
              <p className="text-sm text-neutral-400 leading-relaxed">
                Minimal design, structured data, and layouts that scale from
                laptop to SOC screens.
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Home;
