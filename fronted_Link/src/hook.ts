import type { HumanLinkSdkClient } from "./sdk-client.js";
import type {
  HumanLinkApprovalContext,
  HumanLinkFallback,
  HumanLinkRiskPolicy,
} from "./types.js";

interface HookOptions {
  fallback: HumanLinkFallback;
  riskPolicy?: HumanLinkRiskPolicy;
  timeoutSeconds: number;
}

interface HookLogger {
  info?: (msg: string) => void;
  warn?: (msg: string) => void;
}

export function createBeforeToolCallHandler(
  sdkClient: HumanLinkSdkClient,
  options: HookOptions,
  logger: HookLogger = {},
) {
  return async (event: unknown) => {
    const e = asRecord(event);
    const tool = pickToolName(e);
    const params = pickParams(e);

    if (!tool) {
      logger.warn?.("humanlink: skip, tool name not found on before_tool_call payload");
      return;
    }

    const riskLevel = pickRiskLevel(e, tool, params, options.riskPolicy);
    if (riskLevel !== "high") {
      return;
    }

    const command = pickCommand(e, tool, params);
    const context: HumanLinkApprovalContext = {
      tool,
      params,
      risk_level: riskLevel,
      display_summary: command.slice(0, 256),
      origin: "local://openclaw",
      timeout_seconds: options.timeoutSeconds,
    };

    try {
      const approved = await sdkClient.approve({
        command,
        context,
        fallback: options.fallback,
      });

      if (approved) {
        logger.info?.(`humanlink: approved tool call: ${tool}`);
        return;
      }

      if (options.fallback === "allow") {
        logger.warn?.(`humanlink: denied but fallback=allow, continue: ${tool}`);
        return;
      }

      if (options.fallback === "ui") {
        logger.warn?.(`humanlink: denied, fallback=ui, defer to OpenClaw native approval: ${tool}`);
        return;
      }

      throw new Error(`humanlink approval denied: ${tool}`);
    } catch (error) {
      if (options.fallback === "allow") {
        logger.warn?.(`humanlink: sdk error but fallback=allow, continue: ${formatErr(error)}`);
        return;
      }

      if (options.fallback === "ui") {
        logger.warn?.(`humanlink: sdk error, fallback=ui, defer to native approval: ${formatErr(error)}`);
        return;
      }

      throw error instanceof Error ? error : new Error(String(error));
    }
  };
}

function pickToolName(e: Record<string, unknown>): string {
  const direct = e.tool;
  if (typeof direct === "string" && direct.trim()) {
    return direct;
  }

  const name = asRecord(e.toolCall).tool ?? asRecord(e.toolCall).name;
  return typeof name === "string" ? name : "";
}

function pickParams(e: Record<string, unknown>): Record<string, unknown> {
  const candidates = [e.params, e.arguments, asRecord(e.toolCall).params, asRecord(e.toolCall).arguments];
  for (const candidate of candidates) {
    if (isPlainObject(candidate)) {
      return candidate as Record<string, unknown>;
    }
  }
  return {};
}

function pickCommand(e: Record<string, unknown>, tool: string, params: Record<string, unknown>): string {
  const maybeCommand = e.command;
  if (typeof maybeCommand === "string" && maybeCommand.trim()) {
    return maybeCommand;
  }
  return `${tool}: ${safeJson(params)}`.slice(0, 256);
}

function pickRiskLevel(
  e: Record<string, unknown>,
  tool: string,
  params: Record<string, unknown>,
  policy?: HumanLinkRiskPolicy,
): "low" | "medium" | "high" {
  const explicit = String(e.risk_level ?? e.riskLevel ?? "").toLowerCase();
  if (explicit === "high" || explicit === "medium" || explicit === "low") {
    return explicit;
  }

  if (policy?.autoApproveTools?.includes(tool)) {
    return "low";
  }
  if (policy?.highRiskTools?.includes(tool)) {
    return "high";
  }
  if (isHighRiskByPath(params, policy?.highRiskPathPatterns ?? [])) {
    return "high";
  }
  if (isHighRiskByAmount(params, policy)) {
    return "high";
  }

  return "medium";
}

function isHighRiskByPath(params: Record<string, unknown>, patterns: string[]): boolean {
  if (!patterns.length) {
    return false;
  }

  const textValues = Object.values(params).filter((v) => typeof v === "string") as string[];
  return textValues.some((value) => patterns.some((pattern) => value.includes(pattern)));
}

function isHighRiskByAmount(params: Record<string, unknown>, policy?: HumanLinkRiskPolicy): boolean {
  const threshold = policy?.semanticRules?.amountThresholdCents;
  if (typeof threshold !== "number") {
    return false;
  }

  const fields = policy.semanticRules?.amountFields ?? [];
  if (!fields.length) {
    return false;
  }

  return fields.some((field) => {
    const raw = params[field];
    if (typeof raw === "number") {
      return raw >= threshold;
    }
    if (typeof raw === "string") {
      const parsed = Number(raw);
      return Number.isFinite(parsed) && parsed >= threshold;
    }
    return false;
  });
}

function asRecord(value: unknown): Record<string, unknown> {
  return isPlainObject(value) ? (value as Record<string, unknown>) : {};
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return "{}";
  }
}

function formatErr(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}