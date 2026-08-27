// Written by `ralon hook install`. Safe to delete; safe to regenerate.
//
// Refuses any tool call that names a path agent.lock protects. The decision is
// made by `ralon hook check`, which reads the request on stdin and exits 2 to
// refuse — the same check every other agent's hook calls.
import { spawnSync } from "node:child_process";

export const RalonPlugin = async () => ({
  "tool.execute.before": async (input, output) => {
    const request = JSON.stringify({
      tool_name: input?.tool,
      tool_input: output?.args ?? {},
    });

    const result = spawnSync("ralon", ["hook", "check"], {
      input: request,
      encoding: "utf8",
    });

    // A missing binary means the policy cannot be checked. Say so rather than
    // waving the edit through: silence here looks exactly like protection.
    if (result.error) {
      throw new Error(
        "ralon is not on PATH, so agent.lock could not be checked: " +
          result.error.message,
      );
    }

    if (result.status === 2) {
      throw new Error(result.stderr.trim() || "blocked by agent.lock");
    }
  },
});
