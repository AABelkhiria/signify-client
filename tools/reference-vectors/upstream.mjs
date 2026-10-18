// The signify-ts and keripy sources the generators parse for pinned values.
//
// The npm package ships only `dist` and the Python package only its modules, so the generators that
// read `src/`, `test/` or `ref/` need checkouts of the same commits. This module keeps one per
// reference under `upstream/`: a blobless, sparse clone of the directories named below plus the
// repository's root files, detached at the commit the lockfile pins. Each is created on first use
// and moved whenever its pin moves, so a generator never reads a different commit than the one it
// runs against.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { referenceSha } from "./reference.mjs";

/** The keripy commit pinned in uv.lock, which `reference.py` reads for the Python generator. */
function keripySha() {
  const lock = readFileSync(new URL("uv.lock", import.meta.url), "utf8");
  const match = /keripy\.git[^"\n]*#([0-9a-f]{40})"/.exec(lock);
  if (!match) {
    throw new Error("uv.lock does not pin keri to a commit");
  }
  return match[1];
}

const references = {
  "signify-ts": {
    repository: "https://github.com/WebOfTrust/signify-ts.git",
    directories: ["src", "test", "test-integration"],
    sha: () => referenceSha,
  },
  keripy: {
    repository: "https://github.com/WebOfTrust/keripy.git",
    directories: ["src", "ref"],
    sha: keripySha,
  },
};

function git(args, cwd) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} exited with ${result.status}`);
  }
  return result.stdout.trim();
}

function checkedOut(path) {
  if (!existsSync(`${path}.git`)) {
    return "";
  }
  const result = spawnSync("git", ["rev-parse", "HEAD"], { cwd: path, encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : "";
}

/** Makes sure `upstream/<name>/` holds the pinned commit, cloning or moving it as needed. */
export function ensureUpstream(name) {
  const reference = references[name];
  const root = new URL(`upstream/${name}/`, import.meta.url);
  const path = fileURLToPath(root);
  const sha = reference.sha();
  if (checkedOut(path) !== sha) {
    if (!existsSync(`${path}.git`)) {
      git(["clone", "--quiet", "--no-checkout", "--filter=blob:none", "--sparse", reference.repository, path]);
      git(["sparse-checkout", "set", ...reference.directories], path);
    }
    git(["fetch", "--quiet", "--depth", "1", "origin", sha], path);
    git(["checkout", "--quiet", "--detach", sha], path);
  }
  return root;
}

/** The URL of a file or directory inside the pinned signify-ts checkout, fetched first if missing. */
export function upstreamUrl(relative) {
  return new URL(relative, ensureUpstream("signify-ts"));
}

/** The URL of a file or directory inside the pinned keripy checkout, fetched first if missing. */
export function keripyUrl(relative) {
  return new URL(relative, ensureUpstream("keripy"));
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(new URL(process.argv[1], `file://${process.cwd()}/`)) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  for (const name of Object.keys(references)) {
    console.log(`${fileURLToPath(ensureUpstream(name))} at ${references[name].sha()}`);
  }
}
