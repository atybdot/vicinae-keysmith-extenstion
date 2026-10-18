import {
  Action,
  ActionPanel,
  Form,
  Icon,
  List,
  closeMainWindow,
  getPreferenceValues,
  showToast,
  Toast,
} from "@vicinae/api";
import { execFile } from "child_process";
import * as os from "os";
import * as path from "path";
import { useState } from "react";
import { promisify } from "util";
import * as fs from "fs/promises";
import { addKeysmithAccount, base32Decode, normalizeConfigPath } from "./lib/keysmith";
import { parseOtpUrl } from "./lib/otp";
import { decodeQrImage } from "./lib/qr";
import { type VaultSession, legacyMasterPassword, useVault } from "./lib/vault";
import { UnlockForm } from "./components/unlock-form";
import { UnsupportedPlatform } from "./components/unsupported-platform";

const execFileAsync = promisify(execFile);

type AccountFields = {
  account: string;
  issuer: string;
  secret: string;
  type: "totp" | "hotp";
  digits: number;
  timeStep: number;
  counter: number;
  algorithm: string;
};

async function decodeAndApply(
  imagePath: string,
  fill: (fields: AccountFields) => void,
): Promise<boolean> {
  const text = await decodeQrImage(imagePath);
  if (!text) {
    await showToast({
      title: "No QR code found",
      message:
        "Could not find a QR code in that image. Try a clearer screenshot or enter the details manually.",
      style: Toast.Style.Failure,
    });
    return false;
  }
  const url = parseOtpUrl(text);
  if (!url) {
    await showToast({
      title: "Not an OTP QR code",
      message: "The QR code does not contain an OTP setup code.",
      style: Toast.Style.Failure,
    });
    return false;
  }
  fill({
    account: url.account,
    issuer: url.issuer,
    secret: url.secret,
    type: url.type,
    digits: url.digits,
    timeStep: url.timeStep,
    counter: url.counter,
    algorithm: url.algorithm,
  });
  await showToast({
    title: "QR code detected",
    message: "Account details filled in. Review and submit.",
  });
  return true;
}

function normalizeAlgorithm(value: string): string {
  const v = value.toLowerCase().replace(/-/g, "");
  if (v === "sha256") return "Sha256";
  if (v === "sha512") return "Sha512";
  return "Sha1";
}

async function discardScreenshot(file: string): Promise<void> {
  try {
    await fs.unlink(file);
  } catch (error) {
    const code = (error as { code?: unknown } | null | undefined)?.code;
    if (code === "ENOENT") return;
    try {
      await showToast({
        title: "Could not remove screenshot",
        message: `The captured QR screenshot may still contain your secret. Delete it manually: ${file}`,
        style: Toast.Style.Failure,
      });
    } catch {
      // Toast display is best-effort.
    }
  }
}

function AddAccountForm({ configPath, session }: { configPath: string; session: VaultSession }) {
  const [account, setAccount] = useState("");
  const [issuer, setIssuer] = useState("");
  const [secret, setSecret] = useState("");
  const [type, setType] = useState<"totp" | "hotp">("totp");
  const [digits, setDigits] = useState("6");
  const [timeStep, setTimeStep] = useState("30");
  const [counter, setCounter] = useState("0");
  const [algorithm, setAlgorithm] = useState("SHA1");

  function fillForm(fields: AccountFields) {
    setAccount(fields.account);
    setIssuer(fields.issuer);
    setSecret(fields.secret);
    setType(fields.type);
    setDigits(String(fields.digits));
    setTimeStep(String(fields.timeStep));
    setCounter(String(fields.counter));
    setAlgorithm(fields.algorithm);
  }

  async function handleQrFile(paths: string[]) {
    const file = paths[0];
    if (!file) return;
    try {
      await decodeAndApply(file, fillForm);
    } catch (error) {
      await showToast({
        title: "Could not read image",
        message: error instanceof Error ? error.message : String(error),
        style: Toast.Style.Failure,
      });
    }
  }

  async function handleScreenshot() {
    const output = path.join(os.tmpdir(), `vicinae-keysmith-qr-${Date.now()}.png`);
    try {
      try {
        await execFileAsync("spectacle", ["-r", "-b", "-n", "-o", output], { timeout: 120000 });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.includes("ENOENT")) {
          await showToast({
            title: "Spectacle not found",
            message: "Install Spectacle or pick a QR image file instead.",
            style: Toast.Style.Failure,
          });
        } else {
          await showToast({
            title: "Screenshot cancelled",
            message: "No screenshot was captured.",
          });
        }
        return;
      }
      try {
        await decodeAndApply(output, fillForm);
      } catch (error) {
        await showToast({
          title: "Could not read screenshot",
          message: error instanceof Error ? error.message : String(error),
          style: Toast.Style.Failure,
        });
      }
    } finally {
      await discardScreenshot(output);
    }
  }

  async function handleSubmit(values: Record<string, unknown>) {
    const name = String(values.account ?? "").trim();
    const issuerValue = String(values.issuer ?? "").trim();
    const secretValue = String(values.secret ?? "")
      .trim()
      .replace(/\s/g, "");
    const otpType = String(values.type ?? "totp") === "hotp" ? "hotp" : "totp";

    if (!name || !secretValue) {
      await showToast({
        title: "Missing fields",
        message: "Scan a QR code or enter the account name and secret.",
        style: Toast.Style.Failure,
      });
      return;
    }

    if (!base32Decode(secretValue)) {
      await showToast({
        title: "Invalid secret",
        message: "The secret must be a valid Base32 code, like the one shown next to the QR code.",
        style: Toast.Style.Failure,
      });
      return;
    }

    const digitsRaw = Number.parseInt(String(values.digits ?? digits), 10);
    const pinLength = Number.isFinite(digitsRaw) && digitsRaw > 0 ? digitsRaw : 6;

    const algorithmValue = normalizeAlgorithm(String(values.algorithm ?? algorithm));

    const periodRaw = Number.parseInt(String(values.timeStep ?? timeStep), 10);
    const timeStepValue = Number.isFinite(periodRaw) && periodRaw > 0 ? periodRaw : 30;

    const counterRaw = Number.parseInt(String(values.counter ?? counter), 10);
    const counterValue = Number.isFinite(counterRaw) && counterRaw >= 0 ? counterRaw : 0;

    try {
      await addKeysmithAccount(configPath, session.key, {
        account: name,
        issuer: issuerValue,
        type: otpType,
        secret: secretValue,
        pinLength,
        hash: algorithmValue,
        ...(otpType === "totp" ? { timeStep: timeStepValue } : { counter: counterValue }),
      });
      await showToast({ title: "Account added", message: "The account was added to Keysmith." });
      await closeMainWindow();
    } catch (error) {
      await showToast({
        title: "Could not add account",
        message: error instanceof Error ? error.message : String(error),
        style: Toast.Style.Failure,
      });
    }
  }

  return (
    <Form
      actions={
        <ActionPanel>
          <Action.SubmitForm title="Add Account" icon={Icon.Plus} onSubmit={handleSubmit} />
          <Action
            title="Scan QR from Screen"
            icon={Icon.Camera}
            shortcut={{ modifiers: ["cmd", "shift"], key: "s" }}
            onAction={handleScreenshot}
          />
        </ActionPanel>
      }
    >
      <Form.Description text="Scan a QR code from a file or straight from the screen, or enter the details manually like in Keysmith or Aegis." />
      <Form.FilePicker
        id="qrImage"
        title="QR Image File"
        allowMultipleSelection={false}
        canChooseDirectories={false}
        onChange={handleQrFile}
      />
      <Form.Description text="Tip: press Cmd+Shift+S or pick Scan QR from Screen to select a QR code on screen with Spectacle." />
      <Form.Separator />
      <Form.TextField
        id="issuer"
        title="Issuer"
        value={issuer}
        onChange={setIssuer}
        placeholder="Google"
      />
      <Form.TextField
        id="account"
        title="Account Name"
        value={account}
        onChange={setAccount}
        placeholder="user@example.com"
      />
      <Form.TextField
        id="secret"
        title="Secret"
        value={secret}
        onChange={setSecret}
        placeholder="Secret shown next to the QR code"
      />
      <Form.Dropdown
        id="type"
        title="Type"
        value={type}
        onChange={(value) => setType(value as "totp" | "hotp")}
      >
        <Form.Dropdown.Item value="totp" title="TOTP (time-based)" />
        <Form.Dropdown.Item value="hotp" title="HOTP (counter-based)" />
      </Form.Dropdown>
      <Form.Dropdown id="algorithm" title="Algorithm" value={algorithm} onChange={setAlgorithm}>
        <Form.Dropdown.Item value="SHA1" title="SHA1" />
        <Form.Dropdown.Item value="SHA256" title="SHA256" />
        <Form.Dropdown.Item value="SHA512" title="SHA512" />
      </Form.Dropdown>
      <Form.TextField
        id="digits"
        title="Digits"
        value={digits}
        onChange={setDigits}
        placeholder="6"
      />
      {type === "totp" ? (
        <Form.TextField
          id="timeStep"
          title="Period (seconds)"
          value={timeStep}
          onChange={setTimeStep}
          placeholder="30"
        />
      ) : (
        <Form.TextField
          id="counter"
          title="Counter"
          value={counter}
          onChange={setCounter}
          placeholder="0"
        />
      )}
    </Form>
  );
}

export default function AddAccount() {
  const preferences = getPreferenceValues<ExtensionPreferences>();
  const configPath = normalizeConfigPath(preferences.configPath);
  const gate = useVault(configPath);

  if (gate.status === "unsupported") {
    return <UnsupportedPlatform />;
  }

  if (gate.status === "loading") {
    return <Form isLoading />;
  }

  if (gate.status === "unlocked" && gate.session) {
    if (!gate.session.verified) {
      return (
        <List>
          <List.EmptyView
            icon={Icon.Warning}
            title="Vault could not be verified"
            description="Your vault has no accounts, so the master password could not be confirmed. Add an account in Keysmith first, then unlock here."
            actions={
              <ActionPanel>
                <Action title="Unlock" icon={Icon.Lock} onAction={() => void gate.lock()} />
              </ActionPanel>
            }
          />
        </List>
      );
    }
    return <AddAccountForm configPath={configPath} session={gate.session} />;
  }

  if (gate.status === "error") {
    return (
      <List>
        <List.EmptyView
          icon={Icon.Warning}
          title="Could not read Keysmith"
          description={gate.error ?? "Unknown error"}
          actions={
            <ActionPanel>
              <Action title="Unlock" icon={Icon.Lock} onAction={() => void gate.lock()} />
            </ActionPanel>
          }
        />
      </List>
    );
  }

  return (
    <UnlockForm
      firstRun={gate.firstRun}
      defaultPassword={gate.firstRun ? legacyMasterPassword() : ""}
      onSubmit={gate.unlock}
    />
  );
}
