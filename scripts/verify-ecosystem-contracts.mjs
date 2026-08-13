import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const emailRoot = process.env.EMAIL_PROVIDER_SERVICE_ROOT;
if (!emailRoot) {
  throw new Error("EMAIL_PROVIDER_SERVICE_ROOT must point to the Email Provider Service checkout");
}

const notificationRoot = resolve(import.meta.dirname, "..");
const names = [
  "lenso.email.dispatch-requested.v1.schema.json",
  "lenso.email.dispatch-observed.v1.schema.json",
  "lenso.email.receipt-observed.v1.schema.json",
];

for (const name of names) {
  const [owned, consumed] = await Promise.all([
    readFile(resolve(notificationRoot, "contracts/events", name)),
    readFile(resolve(emailRoot, "contracts", name)),
  ]);
  if (!owned.equals(consumed)) {
    throw new Error(`Notification and Email Provider contract byte drift: ${name}`);
  }
}

const emailConstants = await readFile(resolve(emailRoot, "src/contracts.ts"), "utf8");
for (const name of names) {
  const eventName = name.replace(".schema.json", "");
  if (!emailConstants.includes(JSON.stringify(eventName))) {
    throw new Error(`Email Provider does not bind the contracted Event name: ${eventName}`);
  }
}

console.log(`Verified ${names.length} Notification to Email Provider contracts`);
