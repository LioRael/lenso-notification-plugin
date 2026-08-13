import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const businessPath = resolve(root, "packages/notification-console/src/notification-business-api.v1.json");
const business = await readFile(businessPath);
const digest = `sha256:${createHash("sha256").update(business).digest("hex")}`;
const [rust, typescript] = await Promise.all([
  readFile(resolve(root, "crates/notification/src/business_api.rs"), "utf8"),
  readFile(resolve(root, "packages/notification-console/src/business-api.ts"), "utf8")
]);
for (const [owner, source] of [["Rust", rust], ["TypeScript", typescript]]) {
  if (!source.includes(digest)) throw new Error(`${owner} Business API digest drift: expected ${digest}`);
}

const generated = JSON.parse(execFileSync(
  "cargo",
  ["run", "--quiet", "-p", "lenso-module-notification", "--example", "console_module_manifest"],
  { cwd: root, encoding: "utf8" }
));
const committed = JSON.parse(await readFile(resolve(root, "packages/notification-console/console-module.json"), "utf8"));
if (JSON.stringify(generated) !== JSON.stringify(committed)) throw new Error("Console manifest drift");

const eventFiles = [
  "lenso.email.dispatch-requested.v1.schema.json",
  "lenso.email.dispatch-observed.v1.schema.json",
  "lenso.email.receipt-observed.v1.schema.json",
  "lenso.organization.invitation-accepted.v1.schema.json",
  "lenso.organization.invitation-revoked.v1.schema.json"
];
for (const file of eventFiles) {
  const schema = JSON.parse(await readFile(resolve(root, "contracts/events", file), "utf8"));
  if (schema.title !== file.replace(".schema.json", "")) throw new Error(`Event title drift: ${file}`);
  if (schema.additionalProperties !== false) throw new Error(`Event contract must be closed: ${file}`);
}
console.log(`Verified Console manifest, Business API ${digest}, and ${eventFiles.length} Event contracts`);
