import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { gzipSync } from "node:zlib";

const root = resolve(import.meta.dirname, "..");
const packageRoot = join(root, "packages", "notification-console");
const distRoot = join(packageRoot, "dist");
const outputRoot = resolve(
  process.env.LENSO_NOTIFICATION_CONSOLE_ARTIFACT_DIR ??
    join(root, "dist", "notification-console-artifact")
);
const moduleReleaseDigest = process.env.LENSO_NOTIFICATION_MODULE_RELEASE_DIGEST;
const locatorBase = process.env.LENSO_CONSOLE_MODULE_ARTIFACT_BASE_URL;

const isDigest = (value) =>
  typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);

if (!isDigest(moduleReleaseDigest)) {
  throw new Error(
    "LENSO_NOTIFICATION_MODULE_RELEASE_DIGEST must be a sha256:<64 hex> digest"
  );
}

const listFiles = async (directory, prefix = "") => {
  const files = [];
  for (const entry of await readdir(join(directory, prefix), {
    withFileTypes: true,
  })) {
    const relative = prefix ? join(prefix, entry.name) : entry.name;
    if (entry.isDirectory()) {
      files.push(...(await listFiles(directory, relative)));
    } else if (entry.isFile()) {
      files.push(relative.replaceAll("\\", "/"));
    }
  }
  return files.sort();
};

const normalizeTimes = async (directory) => {
  const epoch = new Date("1980-01-01T00:00:00.000Z");
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await normalizeTimes(path);
    await utimes(path, epoch, epoch);
  }
  await utimes(directory, epoch, epoch);
};

const manifest = JSON.parse(
  await readFile(join(packageRoot, "console-module.json"), "utf8")
);
if (manifest.moduleId !== "lenso/notification") {
  throw new Error("Notification Console manifest moduleId is invalid");
}

const files = await listFiles(distRoot);
if (!files.includes("index.js")) {
  throw new Error("Build the Notification Console package before packaging it");
}
const styleAssets = files
  .filter((file) => file.endsWith(".css"))
  .map((path, order) => ({ order, path }));

await rm(outputRoot, { force: true, recursive: true });
await mkdir(outputRoot, { recursive: true });
const temporaryRoot = await mkdtemp(join(tmpdir(), "lenso-notification-console-"));
try {
  const archivePackageRoot = join(temporaryRoot, "package");
  await mkdir(archivePackageRoot, { recursive: true });
  await cp(distRoot, join(archivePackageRoot, "dist"), { recursive: true });
  await normalizeTimes(temporaryRoot);
  const archiveName = "lenso-notification.tar.gz";
  const archivePath = join(outputRoot, archiveName);
  const tarPath = join(temporaryRoot, "lenso-notification.tar");
  const ownershipArguments =
    process.platform === "darwin"
      ? ["--uid", "0", "--gid", "0", "--uname", "root", "--gname", "root"]
      : ["--owner=0", "--group=0", "--numeric-owner", "--sort=name"];
  execFileSync("tar", [
    "--format",
    "ustar",
    ...ownershipArguments,
    "-cf",
    tarPath,
    "-C",
    temporaryRoot,
    "package",
  ]);
  await writeFile(archivePath, gzipSync(await readFile(tarPath), { level: 9 }));
  const artifactDigest = `sha256:${createHash("sha256")
    .update(await readFile(archivePath))
    .digest("hex")}`;
  const locator = locatorBase
    ? `${locatorBase.replace(/\/+$/u, "")}/${basename(archivePath)}`
    : null;
  const entries = [
    { name: "module", path: "index.js" },
    ...styleAssets.map((asset) => ({
      name: `style-${asset.order}`,
      path: asset.path,
    })),
  ];
  await writeFile(
    join(outputRoot, "artifact-index.json"),
    `${JSON.stringify(
      {
        artifacts: [
          {
            artifactDigest,
            artifactFile: archiveName,
            entries,
            entry: "index.js",
            format: "console_ui_esm",
            locator,
            manifest,
            moduleId: manifest.moduleId,
            moduleReleaseDigest,
            requestedPermissions: [],
            styleAssets,
          },
        ],
      },
      null,
      2
    )}\n`,
    "utf8"
  );
  process.stdout.write(
    `${JSON.stringify({ artifactDigest, artifactIndex: join(outputRoot, "artifact-index.json") })}\n`
  );
} finally {
  await rm(temporaryRoot, { force: true, recursive: true });
}
