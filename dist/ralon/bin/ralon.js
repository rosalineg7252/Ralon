#!/usr/bin/env node
// Hands over to the platform binary that npm installed as an optional
// dependency. The exit code is passed straight through: ralon's codes are its
// interface (1 = a path is protected, 2 = error), and a hook that swallowed
// them would report every policy as satisfied.
"use strict";

const { spawnSync } = require("node:child_process");

const PACKAGES = {
  "linux-x64": "@stoneware-dev/linux-x64",
  "linux-arm64": "@stoneware-dev/linux-arm64",
  "darwin-x64": "@stoneware-dev/darwin-x64",
  "darwin-arm64": "@stoneware-dev/darwin-arm64",
  "win32-x64": "@stoneware-dev/win32-x64",
};

function binaryPath() {
  const platform = `${process.platform}-${process.arch}`;
  const pkg = PACKAGES[platform];
  if (!pkg) {
    return { error: `no ralon binary is built for ${platform}` };
  }
  const executable = process.platform === "win32" ? "ralon.exe" : "ralon";
  try {
    return { path: require.resolve(`${pkg}/bin/${executable}`) };
  } catch {
    // npm skips optional dependencies whose os/cpu do not match, and silently
    // when an install runs with --no-optional.
    return {
      error:
        `${pkg} is not installed.\n` +
        `Reinstall without --no-optional, or use one of:\n` +
        `  cargo install ralon\n` +
        `  https://github.com/stoneware-dev/Ralon/releases`,
    };
  }
}

const found = binaryPath();
if (found.error) {
  console.error(`ralon: ${found.error}`);
  process.exit(2);
}

const result = spawnSync(found.path, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: true,
});

if (result.error) {
  console.error(`ralon: ${result.error.message}`);
  process.exit(2);
}
// Killed by a signal: report it the way a shell would.
if (result.signal) {
  process.exit(128 + (require("node:os").constants.signals[result.signal] ?? 0));
}
process.exit(result.status ?? 2);
