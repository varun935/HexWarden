import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

export async function analyze(path: string) {
  const { stdout } = await run(process.env.PYTHON ?? "python3", ["-m", "trust_adapter.cli", path], { cwd: process.env.HEXWARDEN_ROOT ?? ".." });
  return JSON.parse(stdout);
}