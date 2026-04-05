import {
  definePluginEntry,
  fetchWithSsrFGuard,
  ssrfPolicyFromAllowPrivateNetwork,
  type OpenClawPluginApi,
} from "./api.js";
import { HumanLinkSdkClient } from "./src/sdk-client.js";
import { createBeforeToolCallHandler } from "./src/hook.js";
import type { HumanLinkPluginConfig } from "./src/types.js";
import { DEFAULTS } from "./src/types.js";

export default definePluginEntry({
  id: "humanlink",
  name: "HumanLink",
  description:
    "Hardware biometric authorization gate — requires physical fingerprint confirmation for high-risk tool calls via HumanLink protocol",
  register(api: OpenClawPluginApi) {
    const cfg = (api.pluginConfig ?? {}) as HumanLinkPluginConfig;

    const sdkUrl = cfg.sdkUrl ?? DEFAULTS.sdkUrl;
    const fallback = cfg.fallback ?? DEFAULTS.fallback;
    const timeoutSeconds = cfg.timeoutSeconds ?? DEFAULTS.timeoutSeconds;

    // Build an SSRF-safe fetch wrapper targeting the local HumanLink daemon.
    const ssrfPolicy = ssrfPolicyFromAllowPrivateNetwork(true);

    const guardedFetch = async (url: string, init?: RequestInit): Promise<Response> => {
      const { response, release } = await fetchWithSsrFGuard({
        url,
        init,
        timeoutMs: (timeoutSeconds + 5) * 1000, // hard timeout with buffer
        policy: ssrfPolicy,
        auditContext: "humanlink",
      });
      // Release the guarded-fetch slot immediately; we consume the body inline.
      try {
        return response;
      } finally {
        await release();
      }
    };

    const sdkClient = new HumanLinkSdkClient(
      { fetch: guardedFetch },
      { sdkUrl, timeoutSeconds },
    );

    const handler = createBeforeToolCallHandler(
      sdkClient,
      { fallback, riskPolicy: cfg.riskPolicy, timeoutSeconds },
      { info: api.logger.info, warn: api.logger.warn },
    );

    api.on("before_tool_call", handler);

    api.logger.info?.("humanlink: plugin registered, gating high-risk tool calls");
  },
});
