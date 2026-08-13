import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const buildRoot = resolve(
  process.env.LENSO_NOTIFICATION_BUILD_ROOT ?? root
);
const frameworkRoot = process.env.LENSO_FRAMEWORK_ROOT?.trim();
const artifactRoot = resolve(
  process.env.LENSO_NOTIFICATION_CONSOLE_ARTIFACT_DIR ??
    join(root, "dist", "notification-console-artifact")
);
const outputRoot = resolve(
  process.env.LENSO_NOTIFICATION_RELEASE_DIR ??
    join(root, "dist", "notification-release")
);

const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
};
const digestBytes = (bytes) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const digestJson = (value) => digestBytes(Buffer.from(canonicalJson(value)));

// The Console archive bytes do not contain the external artifact index, so the
// release binding can be finalized after the deterministic archive is built.
// Keep this orchestration here so authors do not need to manually seed a digest
// or understand the two-phase content-addressing order.
const placeholderReleaseDigest = `sha256:${"0".repeat(64)}`;
execFileSync("pnpm", ["build"], { cwd: root, stdio: "inherit" });
execFileSync(process.execPath, [join(root, "scripts", "build-console-artifact.mjs")], {
  cwd: root,
  env: {
    ...process.env,
    LENSO_NOTIFICATION_MODULE_RELEASE_DIGEST: placeholderReleaseDigest,
  },
  stdio: "inherit",
});

const artifactIndexPath = join(artifactRoot, "artifact-index.json");
const artifactIndex = JSON.parse(await readFile(artifactIndexPath, "utf8"));
const artifact = artifactIndex.artifacts?.find(
  (value) => value.moduleId === "lenso/notification"
);
if (!artifact) throw new Error("Notification Console artifact is missing");
const archivePath = join(artifactRoot, artifact.artifactFile);
if (digestBytes(await readFile(archivePath)) !== artifact.artifactDigest) {
  throw new Error("Notification Console artifact digest is stale");
}

const cargoConfig = frameworkRoot
  ? [
      "--config",
      `patch.crates-io.lenso.path=${JSON.stringify(
        join(resolve(frameworkRoot), "crates", "lenso")
      )}`,
    ]
  : [];
const manifest = JSON.parse(
  execFileSync(
    "cargo",
    [
      ...cargoConfig,
      "run",
      "--quiet",
      "-p",
      "lenso-module-notification",
      "--example",
      "module_manifest",
    ],
    { cwd: buildRoot, encoding: "utf8" }
  )
);
const manifestDigest = digestJson(manifest);
execFileSync(
  "cargo",
  [
    ...cargoConfig,
    "package",
    "--locked",
    "-p",
    "lenso-module-notification",
    "--allow-dirty",
    "--no-verify",
  ],
  { cwd: buildRoot, stdio: "inherit" }
);
const cratePath = join(
  buildRoot,
  "target",
  "package",
  "lenso-module-notification-0.1.0.crate"
);
const migrationPath = join(
  root,
  "crates",
  "notification",
  "migrations",
  "0001_create_notification_schema.sql"
);
const contractDigest =
  "sha256:ebbbec96b0657a1158850b1fddbee702367387dfb7f610c9c1ab15d4200089f5";
const release = {
  protocol: "lenso.module-release.v1",
  module_id: "lenso/notification",
  version: "0.1.0",
  manifest,
  manifest_digest: manifestDigest,
  delivery: {
    kind: "linked",
    package: "lenso-module-notification",
    crate_version: "0.1.0",
    archive_checksum: digestBytes(await readFile(cratePath)),
    default_features: false,
    features: [],
    binding: "notification::linked_module",
    migrations: [
      {
        locator: "migrations/0001_create_notification_schema.sql",
        digest: digestBytes(await readFile(migrationPath)),
      },
    ],
  },
  console_ui_artifact: {
    artifact: {
      locator: artifact.locator ?? artifact.artifactFile,
      digest: artifact.artifactDigest,
    },
    format: "console_ui_esm",
    protocol_major: 1,
    entry: artifact.entry,
    entries: artifact.entries,
    styleAssets: artifact.styleAssets,
    manifest: artifact.manifest,
    requested_permissions: artifact.requestedPermissions,
    provenance: [],
  },
  compatibility: {
    lenso_requirement: ">=0.3.42",
    host_api_requirement: "^2.1.0",
    console_ui_requirement: "^2.0.0",
    rust_requirement: ">=1.94",
    targets: [],
    transports: [],
    protocol_digests: [contractDigest],
  },
  provenance: [],
};
const moduleReleaseDigest = digestJson(release);
const surfaceApiGrant = {
  artifactDigest: artifact.artifactDigest,
  moduleReleaseDigest,
  contractDigest,
  operationIds: [
    "notification/http/GET:/deliveries",
    "notification/http/GET:/deliveries/{id}",
    "notification/http/POST:/deliveries/{id}/retry",
  ],
  contractArtifact: {
    format: "openapi_3_1_json",
    document: await readFile(
      join(
        root,
        "packages",
        "notification-console",
        "src",
        "notification-business-api.v1.json"
      ),
      "utf8"
    ),
  },
};

artifact.moduleReleaseDigest = moduleReleaseDigest;
await mkdir(outputRoot, { recursive: true });
await Promise.all([
  writeFile(artifactIndexPath, `${JSON.stringify(artifactIndex, null, 2)}\n`, "utf8"),
  writeFile(
    join(outputRoot, "lenso.module-release.json"),
    `${JSON.stringify(release, null, 2)}\n`,
    "utf8"
  ),
  writeFile(
    join(outputRoot, "surface-api-grant.json"),
    `${JSON.stringify(surfaceApiGrant, null, 2)}\n`,
    "utf8"
  ),
]);
process.stdout.write(
  `${JSON.stringify({ artifactDigest: artifact.artifactDigest, moduleReleaseDigest })}\n`
);
