export type HumanLinkFallback = "deny" | "ui" | "allow";

export interface HumanLinkRiskSemanticRules {
  amountThresholdCents?: number;
  amountFields?: string[];
}

export interface HumanLinkRiskPolicy {
  semanticRules?: HumanLinkRiskSemanticRules;
  highRiskTools?: string[];
  autoApproveTools?: string[];
  highRiskPathPatterns?: string[];
}

export interface HumanLinkPluginConfig {
  sdkUrl?: string;
  fallback?: HumanLinkFallback;
  timeoutSeconds?: number;
  riskPolicy?: HumanLinkRiskPolicy;
}

export interface HumanLinkApprovalContext {
  tool: string;
  params: Record<string, unknown>;
  risk_level: "low" | "medium" | "high";
  display_summary?: string;
  origin?: string;
  timeout_seconds?: number;
}

export const DEFAULTS = {
  sdkUrl: "http://127.0.0.1:8765",
  fallback: "deny" as HumanLinkFallback,
  timeoutSeconds: 30,
} as const;