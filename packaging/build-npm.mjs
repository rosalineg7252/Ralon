#!/usr/bin/env node
// Assembles the npm packages from binaries the release workflow already built.
//
//   node packaging/build-npm.mjs --version 0.1.1 --binaries artifacts --out dist
//
// `binaries` holds one directory per Rust target, each containing the
// executable. Produces dist/platforms/<name> (one package per platform, each
// carrying a binary) and dist/ralon (the package users install, whose
// optionalDependencies point at them). npm then installs only the one whose
// os/cpu match.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function argument(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  if (index !== -1 && process.argv[index + 1]) return process.argv[index + 1];
  if (fallback !== undefined) return fallback;
  throw new Error(`missing --${name}`);
}

const version = argument("version").replace(/^v/, "");
const binaries = argument("binaries", "artifacts");
const out = argument("out", "dist");
const allowMissing = process.argv.includes("--allow-missing");

if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error(`--version ${version} is not a semver version`);
}

const targets = JSON.parse(readFileSync(join(root, "packaging/targets.json"), "utf8"));
const meta = JSON.parse(readFileSync(join(root, "npm/package.json"), "utf8"));

const optionalDependencies = {};
for (const [target, spec] of Object.entries(targets)) {
  const executable = spec.os === "win32" ? "ralon.exe" : "ralon";
  const source = join(binaries, target, executable);

  if (!existsSync(source)) {
    // A meta package pointing at versions that were never published fails at
    // install time, for everyone, on every platform.
    if (!allowMissing) throw new Error(`no binary for ${target} at ${source}`);
    console.warn(`skipping ${target}: ${source} is missing`);
    continue;
  }

  const name = `@stoneware-dev/${spec.npm}`;
  const directory = join(out, "platforms", spec.npm);
  mkdirSync(join(directory, "bin"), { recursive: true });
  copyFileSync(source, join(directory, "bin", executable));

  writeFileSync(
    join(directory, "package.json"),
    JSON.stringify(
      {
        name,
        version,
        description: `${meta.description} (${spec.npm} binary)`,
        license: meta.license,
        repository: meta.repository,
        // npm consults these before downloading: the four packages that do not
        // apply are never fetched.
        os: [spec.os],
        cpu: [spec.cpu],
        files: [`bin/${executable}`],
      },
      null,
      2,
    ) + "\n",
  );

  optionalDependencies[name] = version;
  console.log(`packaged ${name}@${version}`);
}

if (Object.keys(optionalDependencies).length === 0) {
  throw new Error("no binaries were found, so there is nothing to publish");
}

const directory = join(out, "ralon");
mkdirSync(join(directory, "bin"), { recursive: true });
copyFileSync(join(root, "npm/bin/ralon.js"), join(directory, "bin", "ralon.js"));
copyFileSync(join(root, "npm/README.md"), join(directory, "README.md"));
copyFileSync(join(root, "LICENSE"), join(directory, "LICENSE"));
writeFileSync(
  join(directory, "package.json"),
  JSON.stringify({ ...meta, version, optionalDependencies }, null, 2) + "\n",
);

console.log(`packaged ralon@${version}`);
