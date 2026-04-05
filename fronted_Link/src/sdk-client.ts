import type { HumanLinkApprovalContext, HumanLinkFallback } from "./types.js";

export interface HumanLinkSdkTransport {
  fetch: (url: string, init?: RequestInit) => Promise<Response>;
}

export interface HumanLinkSdkClientOptions {
  sdkUrl: string;
  timeoutSeconds: number;
}

export class HumanLinkSdkClient {
  private readonly fetchImpl: HumanLinkSdkTransport["fetch"];
  private readonly sdkUrl: string;
  private readonly timeoutSeconds: number;

  constructor(transport: HumanLinkSdkTransport, options: HumanLinkSdkClientOptions) {
    this.fetchImpl = transport.fetch;
    this.sdkUrl = options.sdkUrl.replace(/\/$/, "");
    this.timeoutSeconds = options.timeoutSeconds;
  }

  async approve(input: {
    command: string;
    context: HumanLinkApprovalContext;
    fallback?: HumanLinkFallback;
  }): Promise<boolean> {
    const response = await this.fetchImpl(`${this.sdkUrl}/auth/approval`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        command: input.command,
        context: input.context,
        fallback: input.fallback,
        timeout_seconds: this.timeoutSeconds,
      }),
    });

    if (!response.ok) {
      const detail = await safeReadText(response);
      throw new Error(`humanlink sdk error ${response.status}: ${detail}`);
    }

    const payload = (await response.json()) as { approved?: boolean };
    return payload.approved === true;
  }
}

async function safeReadText(response: Response): Promise<string> {
  try {
    const text = await response.text();
    return text || "request failed";
  } catch {
    return "request failed";
  }
}