import { LocalStorage } from "@vicinae/api";
import { randomBytes } from "crypto";
import * as fs from "fs";
import { deriveKey, ensureSodium, masterSaltB64, readConfig, verifyKey } from "./keysmith";

/**
 * How long an unlocked vault key is kept around.
 *
 * - `every-time`: nothing is written; the key lives in memory for the view only.
 * - `on-logout`: the key survives until the Vicinae daemon restarts, which
 *   tracks the login session on a per-session service.
 * - `on-reboot`: the key survives until the machine reboots.
 */
export type LockPolicy = "every-time" | "on-logout" | "on-reboot";

export const DEFAULT_LOCK_POLICY: LockPolicy = "on-logout";

export const LOCK_POLICIES: { value: LockPolicy; title: string; description: string }[] = [
  {
    value: "every-time",
    title: "Every time",
    description: "Ask for your password on every launch. Nothing is written to disk.",
  },
  {
    value: "on-logout",
    title: "On logout",
    description: "Remember the unlocked key until the Vicinae session ends.",
  },
  {
    value: "on-reboot",
    title: "On reboot",
    description: "Remember the unlocked key until you reboot.",
  },
];

export function lockPolicyTitle(policy: LockPolicy): string {
  return LOCK_POLICIES.find((entry) => entry.value === policy)?.title ?? policy;
}

/**
 * Result of trying to unlock the vault with a password.
 *
 * - `ok`: the password opened at least one account. The key is trusted.
 * - `nothing-to-verify`: the vault has a master-key section but no accounts to
 *   test against. The key is accepted but could not be confirmed, so it must
 *   never be used to write a new account.
 * - `invalid-password`: an account failed to open. The password is wrong.
 *
 * I/O and parse failures are not represented here. They keep throwing, because
 * they are not authentication failures.
 */
export type UnlockOutcome =
  | { status: "ok"; key: Uint8Array; saltB64: string }
  | { status: "nothing-to-verify"; key: Uint8Array; saltB64: string }
  | { status: "invalid-password" };

/**
 * Derives the vault key from a password and verifies it against the first
 * account section it finds.
 */
export async function unlockVault(configPath: string, password: string): Promise<UnlockOutcome> {
  await ensureSodium();
  const config = readConfig(configPath);
  const master = config["master-key"];
  if (!master) {
    throw new Error("Keysmith.conf is missing the master-key section");
  }

  const { key, saltB64 } = await deriveKey(password, master);
  const verification = verifyKey(config, key);
  if (verification === "invalid") {
    return { status: "invalid-password" };
  }
  if (verification === "nothing-to-verify") {
    return { status: "nothing-to-verify", key, saltB64 };
  }
  return { status: "ok", key, saltB64 };
}

const CACHE_KEY = "keysmith.unlock";
const POLICY_KEY = "keysmith.lockPolicy";
const CACHE_VERSION = 1;

type UnlockCache = {
  v: number;
  key: string;
  salt: string;
  bootId: string;
  daemonStart: string;
};

/**
 * A nonce that lives as long as the extension worker process. It is the fallback
 * session token for the "on logout" policy when the Vicinae daemon start time
 * cannot be read from /proc.
 */
const sessionNonce = randomBytes(16).toString("base64");

/** Contents of /proc/sys/kernel/random/boot_id, or null when unavailable. */
export function bootId(): string | null {
  try {
    return fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  } catch {
    return null;
  }
}

function readProc(pid: number, file: string): string | null {
  try {
    return fs.readFileSync(`/proc/${pid}/${file}`, "utf8");
  } catch {
    return null;
  }
}

/**
 * Reads a numeric field from /proc/<pid>/stat. The comm field (2) can contain
 * spaces and parentheses, so parsing resumes after the last ")".
 */
function statField(pid: number, field: number): string | null {
  const stat = readProc(pid, "stat");
  if (!stat) return null;
  const close = stat.lastIndexOf(")");
  if (close === -1) return null;
  const rest = stat
    .slice(close + 2)
    .trim()
    .split(/\s+/);
  // rest[0] is field 3 (state); field N lives at index N - 3.
  return rest[field - 3] ?? null;
}

function findVicinaePid(): number | null {
  let pid: number | null = process.pid;
  for (let depth = 0; depth < 8 && pid != null && pid > 1; depth++) {
    const comm = readProc(pid, "comm")?.trim();
    if (comm === "vicinae-server" || comm === "vicinae") return pid;
    const ppid = statField(pid, 4);
    pid = ppid != null ? Number.parseInt(ppid, 10) : null;
  }
  return null;
}

/**
 * The Vicinae daemon's start time (field 22 of /proc/<pid>/stat), or null when
 * the daemon cannot be found. A new start time means a new login session.
 */
export function daemonStart(): string | null {
  const pid = findVicinaePid();
  return pid != null ? statField(pid, 22) : null;
}

function sessionToken(): string {
  return daemonStart() ?? sessionNonce;
}

async function readCache(): Promise<UnlockCache | null> {
  try {
    const raw = await LocalStorage.getItem<string>(CACHE_KEY);
    if (typeof raw !== "string") return null;
    const parsed = JSON.parse(raw) as Partial<UnlockCache>;
    if (parsed.v !== CACHE_VERSION) return null;
    if (typeof parsed.key !== "string" || typeof parsed.salt !== "string") return null;
    if (typeof parsed.bootId !== "string" || typeof parsed.daemonStart !== "string") return null;
    return parsed as UnlockCache;
  } catch {
    return null;
  }
}

/** Removes the cached key. Used by "Lock now" and by staleness checks. */
export async function clearCache(): Promise<void> {
  await LocalStorage.removeItem(CACHE_KEY);
}

export async function readLockPolicy(): Promise<LockPolicy | null> {
  const value = await LocalStorage.getItem<string>(POLICY_KEY);
  if (value === "every-time" || value === "on-logout" || value === "on-reboot") return value;
  return null;
}

export async function writeLockPolicy(policy: LockPolicy): Promise<void> {
  await LocalStorage.setItem(POLICY_KEY, policy);
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64").values());
}

/**
 * Caches the unlocked key according to the policy, or clears the cache when the
 * policy does not call for one. Only called after a successful unlock.
 */
export async function rememberUnlockedKey(
  outcome: Exclude<UnlockOutcome, { status: "invalid-password" }>,
  policy: LockPolicy,
): Promise<void> {
  if (policy === "every-time") {
    await clearCache();
    return;
  }
  const currentBootId = bootId();
  if (currentBootId == null) {
    // Without a boot id even "on logout" cannot be scoped reliably.
    await clearCache();
    return;
  }
  const entry: UnlockCache = {
    v: CACHE_VERSION,
    key: bytesToBase64(outcome.key),
    salt: outcome.saltB64,
    bootId: currentBootId,
    daemonStart: sessionToken(),
  };
  await LocalStorage.setItem(CACHE_KEY, JSON.stringify(entry));
}

/**
 * Returns the cached key when the policy and the staleness checks allow it,
 * otherwise drops the cache and returns null. Throws on config I/O failures,
 * which the caller surfaces like any other read error.
 */
export async function loadCachedKey(
  configPath: string,
  policy: LockPolicy,
): Promise<Uint8Array | null> {
  if (policy === "every-time") {
    await clearCache();
    return null;
  }

  const entry = await readCache();
  if (!entry) return null;

  const currentSalt = masterSaltB64(readConfig(configPath));
  if (!currentSalt || currentSalt !== entry.salt) {
    // The Keysmith password changed, so the cached key is stale by definition.
    await clearCache();
    return null;
  }

  if (policy === "on-reboot") {
    if (entry.bootId !== bootId()) {
      await clearCache();
      return null;
    }
  }

  if (policy === "on-logout") {
    if (entry.daemonStart !== sessionToken()) {
      await clearCache();
      return null;
    }
  }

  return base64ToBytes(entry.key);
}
