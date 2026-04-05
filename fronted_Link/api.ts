// Plugin SDK barrel — narrow public surface for the humanlink extension.
// Import from here instead of reaching into openclaw core internals.

export { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
export type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
export { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
export { ssrfPolicyFromAllowPrivateNetwork } from "openclaw/plugin-sdk/ssrf-policy";
