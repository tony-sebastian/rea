import { existsSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";

import { spawnOwnedProviderProcess } from "./ProviderProcess.js";
import { PrivateRuntimeRoot } from "./PrivateRuntimeRoot.js";

import {
  hasWindowsNativeAuthority,
  setVerifiedWindowsNativeAuthority,
  setVerifiedWindowsNativeAuthorityForTest,
  verifiedWindowsNativeCapabilities,
  WINDOWS_NATIVE_AUTHORITY_UNAVAILABLE_REASON,
} from "./WindowsAuthority.js";
import {
  ensureWindowsNativeAuthorityHelper,
  parseCapabilityVerdict,
  resolveWindowsNativeAuthorityHelperSource,
  WINDOWS_AUTHORITY_HELPER_ENV,
} from "./WindowsNativeAuthority.js";

const provenSet = () =>
  ({
    job_object_process_ownership: {
      available: true,
      reason: null,
      proof: "native-authority",
    },
    private_runtime_dacl: {
      available: true,
      reason: null,
      proof: "native-authority",
    },
    reparse_safe_path_admission: {
      available: true,
      reason: null,
      proof: "native-authority",
    },
  }) as const;

describe("parseCapabilityVerdict", () => {
  it("accepts a full native-authority verdict", () => {
    const parsed = parseCapabilityVerdict(provenSet());
    for (const key of Object.keys(parsed)) {
      expect(parsed[key as keyof typeof parsed].available).toBe(true);
      expect(parsed[key as keyof typeof parsed].proof).toBe("native-authority");
    }
  });

  it("fails closed when a control lacks native-authority proof", () => {
    const verdict = {
      ...provenSet(),
      private_runtime_dacl: {
        available: true,
        reason: null,
        proof: "trust-me",
      },
    };
    const parsed = parseCapabilityVerdict(verdict);
    expect(parsed.private_runtime_dacl.available).toBe(false);
    expect(parsed.private_runtime_dacl.proof).toBe("not-proven");
    expect(parsed.job_object_process_ownership.available).toBe(true);
  });

  it("fails closed on non-object verdicts and missing controls", () => {
    expect(parseCapabilityVerdict(null).private_runtime_dacl.available).toBe(
      false,
    );
    expect(
      parseCapabilityVerdict({}).job_object_process_ownership.available,
    ).toBe(false);
    const parsed = parseCapabilityVerdict("nope");
    expect(parsed.reparse_safe_path_admission.reason).toBeTruthy();
  });

  it("propagates the helper's failure reason", () => {
    const parsed = parseCapabilityVerdict({
      job_object_process_ownership: {
        available: false,
        reason: "CreateJobObject: access denied",
        proof: "not-proven",
      },
    });
    expect(parsed.job_object_process_ownership.reason).toBe(
      "CreateJobObject: access denied",
    );
  });
});

describe("verified gate state", () => {
  afterEach(() => {
    setVerifiedWindowsNativeAuthorityForTest(undefined);
  });

  it("starts unproven and flips only after a verified set is published", () => {
    if (process.platform !== "win32") return; // POSIX hosts use the stub
    expect(hasWindowsNativeAuthority("win32")).toBe(false);
    setVerifiedWindowsNativeAuthority("win32", provenSet());
    expect(hasWindowsNativeAuthority("win32")).toBe(true);
    const diagnostics = verifiedWindowsNativeCapabilities("win32");
    expect(diagnostics.private_runtime_dacl.proof).toBe("native-authority");
  });

  it("reports the unproven stub reason before verification", () => {
    if (process.platform !== "win32") return;
    const stub = verifiedWindowsNativeCapabilities("win32");
    expect(stub.private_runtime_dacl.reason).toBe(
      WINDOWS_NATIVE_AUTHORITY_UNAVAILABLE_REASON,
    );
  });
});

describe("ensureWindowsNativeAuthorityHelper", () => {
  it("prefers an explicit prebuilt override", async () => {
    const previous = process.env[WINDOWS_AUTHORITY_HELPER_ENV];
    try {
      process.env[WINDOWS_AUTHORITY_HELPER_ENV] = "does-not-exist.exe";
      expect(await ensureWindowsNativeAuthorityHelper()).toBe(
        "does-not-exist.exe",
      );
    } finally {
      if (previous === undefined)
        delete process.env[WINDOWS_AUTHORITY_HELPER_ENV];
      else process.env[WINDOWS_AUTHORITY_HELPER_ENV] = previous;
    }
  });

  it("finds the packaged C# source on every supported host layout", () => {
    // The helper source must ship with the package; without it Windows
    // authority stays unproven and the provider gates closed.
    if (process.platform !== "win32") return;
    expect(
      resolveWindowsNativeAuthorityHelperSource()?.endsWith(
        "ReaWindowsAuthority.cs",
      ),
    ).toBe(true);
  });
});

describe("windows integration (compiled helper)", () => {
  it.skipIf(process.platform !== "win32")(
    "routes owned spawns through the kill-on-close job helper",
    async () => {
      // The helper compiles on first use; the spawn must exit with the
      // child's own code and mark the ownership as job-spawned.
      const spawned = await spawnOwnedProviderProcess({
        command: "cmd.exe",
        arguments: ["/d", "/s", "/c", "exit 3"],
        runId: "windows-authority-test",
        expectedCommand: null,
      });
      expect(spawned.ownership.jobSpawned).toBe(true);
      const code = await new Promise<number>((resolve, reject) => {
        spawned.process.once("exit", (exitCode) => resolve(exitCode ?? -1));
        spawned.process.once("error", reject);
      });
      expect(code).toBe(3);
    },
    180_000,
  );

  it.skipIf(process.platform !== "win32")(
    "creates and removes a private DACL-protected runtime root",
    async () => {
      const root = await PrivateRuntimeRoot.create({
        prefix: "rea-winauth-test-",
      });
      try {
        expect(existsSync(root.path)).toBe(true);
      } finally {
        await root.close();
      }
      expect(existsSync(root.path)).toBe(false);
    },
    120_000,
  );
});
