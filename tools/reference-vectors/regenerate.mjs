// Runs every fixture generator against the pinned references; with --check, fails if any fixture changed.
// The Node generators run against the signify-ts pinned in package.json, reading its sources from the
// checkout `upstream.mjs` keeps; the Python one runs through `uv run` against the keripy pinned in
// pyproject.toml.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { ensureUpstream } from "./upstream.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = fileURLToPath(new URL("../..", import.meta.url));
const skipped = new Set(["reference.mjs", "regenerate.mjs", "upstream.mjs", "reference.py"]);
const generators = readdirSync(here)
  .filter((name) => /\.(mjs|py)$/.test(name) && !skipped.has(name))
  .sort();

// pysodium finds libsodium through the dynamic loader. On macOS the shell npm runs scripts through
// drops DYLD_* variables, so the Homebrew library directories are offered as a fallback here.
const pythonEnv = { ...process.env };
if (process.platform === "darwin") {
  const fallback = [process.env.DYLD_FALLBACK_LIBRARY_PATH, "/opt/homebrew/lib", "/usr/local/lib"];
  pythonEnv.DYLD_FALLBACK_LIBRARY_PATH = fallback.filter(Boolean).join(":");
}

function run(command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, stdio: "inherit" });
  if (result.error) {
    throw result.error;
  }
  return result.status ?? 1;
}

ensureUpstream("signify-ts");
ensureUpstream("keripy");

for (const generator of generators) {
  const status = generator.endsWith(".py")
    ? run("uv", ["run", "--locked", "python", generator, "--write"], here, pythonEnv)
    : run(process.execPath, [generator, "--write"], here);
  if (status !== 0) {
    process.exit(1);
  }
}

if (process.argv.includes("--check")) {
  process.exit(run("git", ["diff", "--exit-code", "--stat", "--", "fixtures"], root));
}
