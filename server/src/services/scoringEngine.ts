import type { ProviderExecutionResult, ProviderExecutionStatus } from "./providerExecutor";

export type ProviderVerdict = "benign" | "suspicious" | "malicious" | "unknown";
export type ProviderConfidence = "low" | "medium" | "high";
export type TrustLevel = "low" | "medium" | "high";
export type FinalVerdict = "benign" | "suspicious" | "malicious" | "unknown";

export interface ProviderSignal {
  provider: string;
  verdict: ProviderVerdict;
  confidence: ProviderConfidence;
  status: ProviderExecutionStatus;
}

export interface ScoringInput {
  providers: ProviderExecutionResult<NormalizedProviderResponse>[];
}

export interface NormalizedProviderResponse {
  provider_name: string;
  verdict: ProviderVerdict;
  score?: number;
  confidence?: number;
  summary?: string;
  tags?: string[];
}

export interface ScoringResult {
  finalScore: number | null;
  verdict: FinalVerdict;
  confidence: "high" | "medium" | "low";
  processedProviders: ProcessedProvider[];
  meta: {
    totalProviders: number;
    successfulProviders: number;
    failedProviders: number;
    timedOutProviders: number;
    singleProviderMode: boolean;
    hasConflictingSignals: boolean;
  };
}

export interface ProcessedProvider {
  provider: string;
  status: ProviderExecutionStatus;
  normalizedScore: number | null;
  effectiveWeight: number | null;
  verdict: ProviderVerdict | null;
  confidence: ProviderConfidence | null;
}

const VERDICT_SCORES: Record<ProviderVerdict, number> = {
  malicious: 100,
  suspicious: 60,
  unknown: 30,
  benign: 0,
};

const TRUST_WEIGHTS: Record<TrustLevel, number> = {
  high: 1.0,
  medium: 0.7,
  low: 0.5,
};

const CONFIDENCE_MULTIPLIERS: Record<ProviderConfidence, number> = {
  high: 1.0,
  medium: 0.75,
  low: 0.5,
};

const VERDICT_THRESHOLDS = {
  benign: { min: 0, max: 29 },
  suspicious: { min: 30, max: 69 },
  malicious: { min: 70, max: 100 },
} as const;

const DEFAULT_TRUST_LEVEL: TrustLevel = "medium";

function mapConfidenceToLevel(confidence: number | undefined): ProviderConfidence {
  if (confidence === undefined || confidence === null) {
    return "medium";
  }
  if (confidence >= 70) return "high";
  if (confidence >= 40) return "medium";
  return "low";
}

function getProviderTrustLevel(_providerName: string): TrustLevel {
  return DEFAULT_TRUST_LEVEL;
}

function normalizeVerdictToScore(verdict: ProviderVerdict): number {
  return VERDICT_SCORES[verdict] ?? VERDICT_SCORES.unknown;
}

function calculateEffectiveWeight(
  trustLevel: TrustLevel,
  confidence: ProviderConfidence
): number {
  const trustWeight = TRUST_WEIGHTS[trustLevel];
  const confidenceMultiplier = CONFIDENCE_MULTIPLIERS[confidence];
  return trustWeight * confidenceMultiplier;
}

function mapScoreToVerdict(score: number): FinalVerdict {
  if (score >= VERDICT_THRESHOLDS.malicious.min) return "malicious";
  if (score >= VERDICT_THRESHOLDS.suspicious.min) return "suspicious";
  return "benign";
}

function extractProviderSignal(
  result: ProviderExecutionResult<NormalizedProviderResponse>
): ProviderSignal | null {
  if (result.status !== "success" || !result.data) {
    return null;
  }

  const data = result.data;
  const verdict: ProviderVerdict = data.verdict ?? "unknown";
  const confidence = mapConfidenceToLevel(data.confidence);

  return {
    provider: result.provider,
    verdict,
    confidence,
    status: result.status,
  };
}

export function computeScore(input: ScoringInput): ScoringResult {
  const { providers } = input;

  const totalProviders = providers.length;
  let successfulProviders = 0;
  let failedProviders = 0;
  let timedOutProviders = 0;

  const processedProviders: ProcessedProvider[] = [];
  const validSignals: Array<{ normalizedScore: number; effectiveWeight: number }> = [];

  for (const result of providers) {
    if (result.status === "success") {
      successfulProviders++;
    } else if (result.status === "timeout") {
      timedOutProviders++;
    } else {
      failedProviders++;
    }

    const signal = extractProviderSignal(result);

    if (signal) {
      const trustLevel = getProviderTrustLevel(signal.provider);
      const normalizedScore = normalizeVerdictToScore(signal.verdict);
      const effectiveWeight = calculateEffectiveWeight(trustLevel, signal.confidence);

      validSignals.push({ normalizedScore, effectiveWeight });

      processedProviders.push({
        provider: result.provider,
        status: result.status,
        normalizedScore,
        effectiveWeight,
        verdict: signal.verdict,
        confidence: signal.confidence,
      });
    } else {
      processedProviders.push({
        provider: result.provider,
        status: result.status,
        normalizedScore: null,
        effectiveWeight: null,
        verdict: null,
        confidence: null,
      });
    }
  }

  if (validSignals.length === 0) {
    return {
      finalScore: null,
      verdict: "unknown",
      confidence: "low",
      processedProviders,
      meta: {
        totalProviders,
        successfulProviders,
        failedProviders,
        timedOutProviders,
        singleProviderMode: false,
        hasConflictingSignals: false,
      },
    };
  }

  const singleProviderMode = validSignals.length === 1;

  const sumWeightedScores = validSignals.reduce(
    (sum, s) => sum + s.normalizedScore * s.effectiveWeight,
    0
  );
  const sumWeights = validSignals.reduce(
    (sum, s) => sum + s.effectiveWeight,
    0
  );

  const finalScore = sumWeights > 0 
    ? Math.round(sumWeightedScores / sumWeights) 
    : 0;

  const clampedScore = Math.max(0, Math.min(100, finalScore));
  let verdict = mapScoreToVerdict(clampedScore);

  const scores = validSignals.map(s => s.normalizedScore);
  const hasHighThreat = scores.some(s => s >= 70);
  const hasLowThreat = scores.some(s => s <= 29);
  const hasConflictingSignals = hasHighThreat && hasLowThreat;

  if (hasConflictingSignals) {
    verdict = "suspicious";
  }

  let resultConfidence: "high" | "medium" | "low" = "high";
  if (singleProviderMode) {
    resultConfidence = "low";
  } else if (validSignals.length === 2 || hasConflictingSignals) {
    resultConfidence = "medium";
  }

  return {
    finalScore: clampedScore,
    verdict,
    confidence: resultConfidence,
    processedProviders,
    meta: {
      totalProviders,
      successfulProviders,
      failedProviders,
      timedOutProviders,
      singleProviderMode,
      hasConflictingSignals,
    },
  };
}
