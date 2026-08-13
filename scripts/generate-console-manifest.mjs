import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const output = execFileSync(
  "cargo",
  ["run", "--quiet", "-p", "lenso-module-notification", "--example", "console_module_manifest"],
  { cwd: root, encoding: "utf8" }
);
const target = resolve(root, "packages/notification-console/console-module.json");
await mkdir(resolve(root, "packages/notification-console"), { recursive: true });
await writeFile(target, output, "utf8");
