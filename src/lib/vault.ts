import { deriveKey, ensureSodium, readConfig, verifyKey } from "./keysmith";

/**
 * Result of trying to unlock the vault with a password.
 *
 * - `ok`: the password opened at least one account. The key is trusted.
 * - `nothing-to-verify`: the vault has a master-key section but no accounts to
 *   test against. The key is accepted but could not be confirmed.
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
