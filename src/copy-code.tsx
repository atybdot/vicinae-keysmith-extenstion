import {
  Action,
  ActionPanel,
  Clipboard,
  Color,
  Icon,
  List,
  Toast,
  getPreferenceValues,
  showToast,
} from "@vicinae/api";
import { execFile } from "child_process";
import { createHmac } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { useEffect, useMemo, useState } from "react";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

type KeysmithAccount = {
  id: string;
  account: string;
  issuer: string;
  type: "totp" | "hotp" | string;
  hash: "Sha1" | "Sha256" | "Sha512" | string;
  pinLength: number;
  epoch: string;
  timeStep?: number;
  counter?: number;
  secretB64: string;
};

type CodeItem = {
  account: KeysmithAccount;
  code: string;
  validFor?: number;
};

function normalizeConfigPath(value?: string): string {
  return value?.trim() || "~/.config/org.kde.keysmith/Keysmith.conf";
}

function findDecryptScript(): string {
  const candidates = [
    path.resolve(__dirname, "assets", "decrypt_keysmith.py"),
    path.resolve(__dirname, "..", "assets", "decrypt_keysmith.py"),
    path.resolve(__dirname, "..", "..", "assets", "decrypt_keysmith.py"),
    path.resolve(process.cwd(), "assets", "decrypt_keysmith.py"),
    path.resolve(__dirname, "scripts", "decrypt_keysmith.py"),
    path.resolve(__dirname, "..", "scripts", "decrypt_keysmith.py"),
    path.resolve(__dirname, "..", "..", "scripts", "decrypt_keysmith.py"),
    path.resolve(process.cwd(), "scripts", "decrypt_keysmith.py"),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return candidates[0];
}

function incrementHotpCounter(accountId: string): Promise<{ ok: boolean; error: string }> {
  const configPath = normalizeConfigPath(getPreferenceValues<ExtensionPreferences>().configPath);
  return execFileAsync("python3", [findDecryptScript(), "--increment-hotp", accountId], {
    env: {
      ...process.env,
      KEYSMITH_CONFIG: configPath,
    },
  })
    .then(() => ({ ok: true, error: "" }))
    .catch((err) => ({
      ok: false,
      error: err?.stderr || err?.message || "Failed to update counter",
    }));
}

function hashName(hash: string): "sha1" | "sha256" | "sha512" {
  const value = hash.toLowerCase();
  if (value === "sha256") return "sha256";
  if (value === "sha512") return "sha512";
  return "sha1";
}

function otp(secret: Buffer, counter: number, digits: number, hash: string): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac(hashName(hash), secret).update(msg).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

function totp(account: KeysmithAccount, now: number): { code: string; validFor: number } {
  const period = account.timeStep ?? 30;
  const epoch = Number.isFinite(Date.parse(account.epoch))
    ? Math.floor(Date.parse(account.epoch) / 1000)
    : 0;
  const counter = Math.floor((now - epoch) / period);
  const validFor = period - ((now - epoch) % period);
  return {
    code: otp(Buffer.from(account.secretB64, "base64"), counter, account.pinLength, account.hash),
    validFor,
  };
}

function hotp(account: KeysmithAccount): { code: string } {
  return {
    code: otp(
      Buffer.from(account.secretB64, "base64"),
      account.counter ?? 0,
      account.pinLength,
      account.hash,
    ),
  };
}

export default function CopyCode() {
  const preferences = getPreferenceValues<ExtensionPreferences>();
  const [accounts, setAccounts] = useState<KeysmithAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const [refreshCount, setRefreshCount] = useState(0);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    setError(null);

    execFileAsync("python3", [findDecryptScript()], {
      env: {
        ...process.env,
        KEYSMITH_PASSWORD: preferences.masterPassword,
        KEYSMITH_CONFIG: normalizeConfigPath(preferences.configPath),
      },
      maxBuffer: 10 * 1024 * 1024,
    })
      .then(({ stdout }) => {
        const parsed = JSON.parse(stdout) as KeysmithAccount[];
        if (mounted) setAccounts(parsed);
      })
      .catch((err) => {
        const message = err?.stderr || err?.message || "Failed to read Keysmith";
        if (mounted) setError(message);
        showToast({
          style: Toast.Style.Failure,
          title: "Keysmith",
          message: message.slice(0, 400),
        });
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [preferences.masterPassword, preferences.configPath, refreshCount]);

  useEffect(() => {
    const interval = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(interval);
  }, []);

  const items = useMemo<CodeItem[]>(() => {
    const now = Math.floor(Date.now() / 1000);
    return accounts.map((account) => {
      if (account.type === "hotp") {
        return { account, ...hotp(account) };
      }
      return { account, ...totp(account, now) };
    });
  }, [accounts, tick]);

  if (error) {
    return (
      <List>
        <List.EmptyView
          icon={Icon.Warning}
          title="Could not read Keysmith"
          description={error}
          actions={
            <ActionPanel>
              <Action
                title="Reload"
                icon={Icon.ArrowClockwise}
                onAction={() => setRefreshCount((n) => n + 1)}
              />
            </ActionPanel>
          }
        />
      </List>
    );
  }

  if (loading) {
    return <List isLoading />;
  }

  return (
    <List searchBarPlaceholder="Search Keysmith accounts...">
      <List.Section
        title={`OTP Codes (${items.length})`}
        subtitle="Type the account or issuer name to filter."
      >
        {items.map((item) => (
          <List.Item
            key={item.account.id}
            title={item.account.issuer || item.account.account}
            subtitle={item.account.account}
            icon={Icon.Key}
            accessories={
              item.account.type === "totp"
                ? [
                    { text: item.code },
                    {
                      tag: {
                        value: `${String(item.validFor ?? 0).padStart(2, "0")}s`,
                        color: (item.validFor ?? 60) < 10 ? Color.Red : Color.SecondaryText,
                      },
                    },
                  ]
                : [
                    { text: item.code },
                    { text: `C:${String(item.account.counter ?? 0).padStart(2, "0")}` },
                  ]
            }
            actions={
              <ActionPanel>
                {item.account.type === "hotp" ? (
                  <Action
                    title="Use Code and Increment"
                    icon={Icon.ArrowRight}
                    onAction={async () => {
                      await Clipboard.copy(item.code);
                      const result = await incrementHotpCounter(item.account.id);
                      if (!result.ok) {
                        await showToast({
                          style: Toast.Style.Failure,
                          title: "Keysmith",
                          message: result.error,
                        });
                      } else {
                        setRefreshCount((n) => n + 1);
                      }
                    }}
                  />
                ) : null}
                <Action.CopyToClipboard title="Copy Code" content={item.code} />
                <Action
                  title="Reload Keysmith Data"
                  icon={Icon.ArrowClockwise}
                  onAction={() => {
                    setLoading(true);
                    setError(null);
                    setRefreshCount((n) => n + 1);
                  }}
                />
              </ActionPanel>
            }
          />
        ))}
      </List.Section>
    </List>
  );
}
