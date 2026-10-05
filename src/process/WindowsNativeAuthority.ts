import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import {
  setVerifiedWindowsNativeAuthority,
  windowsNativeCapabilities,
  type WindowsNativeCapability,
  type WindowsNativeCapabilitySet,
} from "./WindowsAuthority.js";

const execFileAsync = promisify(execFile);

/** The helper ships as C# source and is compiled on first use by csc.exe. */
const HELPER_SOURCE_RELATIVE_URL =
  "../../bridge/windows/ReaWindowsAuthority.cs";
const HELPER_CACHE_DIRNAME = "windows-authority";
const HELPER_BINARY_NAME = "rea-winauth.exe";

export const WINDOWS_AUTHORITY_HELPER_ENV = "REA_WINAUTH_HELPER";

/** Injectable helper invocation seam used by deterministic unit tests. */
export type WindowsAuthorityHelperRunner = (
  helperPath: string,
) => Promise<unknown>;

let memoizedHelper: string | null | undefined;

/** The packaged helper source, or null when absent. */
export const resolveWindowsNativeAuthorityHelperSource = (): string | null => {
  const source = fileURLToPath(
    new URL(HELPER_SOURCE_RELATIVE_URL, import.meta.url),
  );
  return existsSync(source) ? source : null;
};

/** Locate the system C# compiler shipped with every Windows host. */
const resolveSystemCsc = (): string | null => {
  const windir = process.env.WINDIR ?? "C:\\Windows";
  const framework64 = join(windir, "Microsoft.NET", "Framework64");
  const candidates: string[] = [];
  try {
    if (existsSync(framework64)) {
      for (const entry of readdirSync(framework64))
        candidates.push(join(framework64, entry, "csc.exe"));
    }
  } catch {
    // Directory read failure falls through to the fixed v4 path below.
  }
  candidates.push(
    join(windir, "Microsoft.NET", "Framework", "v4.0.30319", "csc.exe"),
  );
  return candidates.find((candidate) => existsSync(candidate)) ?? null;
};

/**
 * Resolve the native authority helper binary, compiling the packaged C#
 * source with the Windows system compiler on first use and pinning the cache
 * to the source digest. Returns null (fail closed) when neither the source
 * nor a system compiler is available, or when REA_WINAUTH_HELPER names a
 * prebuilt override.
 */
export const ensureWindowsNativeAuthorityHelper = async (): Promise<
  string | null
> => {
  // The prebuilt override is honored live (never memoized) so tests and
  // operators can retarget it without resetting process state.
  const override = process.env[WINDOWS_AUTHORITY_HELPER_ENV];
  if (override !== undefined && override.trim() !== "") return override;
  if (memoizedHelper !== undefined) return memoizedHelper;
  const source = resolveWindowsNativeAuthorityHelperSource();
  if (source === null) {
    memoizedHelper = null;
    return null;
  }
  const cacheDir = join(
    process.env.REA_CACHE_DIR ?? join(homedir(), ".rea", "cache"),
    HELPER_CACHE_DIRNAME,
  );
  const binary = join(cacheDir, HELPER_BINARY_NAME);
  const digestMarker = join(cacheDir, "source.sha256");
  const digest = createHash("sha256")
    .update(readFileSync(source))
    .digest("hex");
  if (
    existsSync(binary) &&
    existsSync(digestMarker) &&
    readFileSync(digestMarker, "utf8").trim() === digest
  ) {
    memoizedHelper = binary;
    return binary;
  }
  const csc = resolveSystemCsc();
  if (csc === null) {
    memoizedHelper = null;
    return null;
  }
  mkdirSync(cacheDir, { recursive: true });
  await execFileAsync(
    csc,
    ["/nologo", "/target:exe", `/out:${binary}`, "/optimize+", source],
    { windowsHide: true, timeout: 120_000 },
  );
  writeFileSync(digestMarker, `${digest}\n`, "utf8");
  memoizedHelper = binary;
  return binary;
};

/**
 * Run the helper's capabilities self-test and publish the verdict.
 *
 * The helper verifies each control against real OS state (job membership
 * readback, security-descriptor readback, handle-based reparse rejection) and
 * reports `proof: "native-authority"` only for controls it demonstrated in
 * that process. Anything unparseable or unproven fails closed to the stub.
 */
export const ensureWindowsNativeAuthority = async (
  platform: NodeJS.Platform = process.platform,
  runner: WindowsAuthorityHelperRunner = defaultRunner,
): Promise<WindowsNativeCapabilitySet> => {
  if (platform !== "win32") return windowsNativeCapabilities(platform);
  const helper = await ensureWindowsNativeAuthorityHelper();
  if (helper === null) return windowsNativeCapabilities(platform);
  const raw = await runner(helper);
  const verified = parseCapabilityVerdict(raw);
  setVerifiedWindowsNativeAuthority(platform, verified);
  return verified;
};

const defaultRunner: WindowsAuthorityHelperRunner = async (helperPath) => {
  const { stdout } = await execFileAsync(helperPath, ["capabilities"], {
    windowsHide: true,
    timeout: 30_000,
  });
  const lines = stdout.split("\n").filter((line) => line.trim() !== "");
  const last = lines.at(-1);
  if (last === undefined) throw new Error("helper produced no verdict");
  return JSON.parse(last) as unknown;
};

/** Required control keys, matching WindowsNativeCapabilitySet exactly. */
const CONTROL_KEYS = [
  "job_object_process_ownership",
  "private_runtime_dacl",
  "reparse_safe_path_admission",
] as const;

export const parseCapabilityVerdict = (
  raw: unknown,
): WindowsNativeCapabilitySet => {
  if (typeof raw !== "object" || raw === null) {
    return failedSet("helper verdict was not an object");
  }
  const record = raw as Record<string, unknown>;
  const set: Record<string, WindowsNativeCapability> = {};
  for (const key of CONTROL_KEYS) {
    set[key] = parseCapability(record[key], key);
  }
  return set as unknown as WindowsNativeCapabilitySet;
};

const parseCapability = (
  raw: unknown,
  key: string,
): WindowsNativeCapability => {
  if (typeof raw !== "object" || raw === null) {
    return unproven(`${key} verdict missing`);
  }
  const { available, reason, proof } = raw as Record<string, unknown>;
  if (available !== true) {
    return unproven(
      typeof reason === "string" && reason !== ""
        ? reason
        : `${key} not proven by helper`,
    );
  }
  if (proof !== "native-authority") {
    return unproven(`${key} claimed without native-authority proof`);
  }
  return { available: true, reason: null, proof: "native-authority" };
};

const failedSet = (reason: string): WindowsNativeCapabilitySet => ({
  job_object_process_ownership: unproven(reason),
  private_runtime_dacl: unproven(reason),
  reparse_safe_path_admission: unproven(reason),
});

const unproven = (reason: string): WindowsNativeCapability => ({
  available: false,
  reason,
  proof: "not-proven",
});

/** Apply a private current-user-only DACL to one runtime path. */
export const applyPrivateRuntimeDacl = async (path: string): Promise<void> => {
  const helper = await ensureWindowsNativeAuthorityHelper();
  if (helper === null) {
    throw new Error(
      "Windows native authority helper is unavailable; cannot establish a private runtime DACL",
    );
  }
  await execFileAsync(helper, ["dacl", "create", "--path", path], {
    windowsHide: true,
    timeout: 15_000,
  });
};

/**
 * Admit paths through handle-based reparse-safe checks before the provider
 * opens them; any reparse component or resolution mismatch fails closed.
 */
export const admitReparseSafePaths = async (
  paths: readonly string[],
): Promise<void> => {
  if (paths.length === 0) return;
  const helper = await ensureWindowsNativeAuthorityHelper();
  if (helper === null) {
    throw new Error(
      "Windows native authority helper is unavailable; cannot admit paths reparse-safe",
    );
  }
  await execFileAsync(helper, ["pathcheck", "--", ...paths], {
    windowsHide: true,
    timeout: 15_000,
  });
};
