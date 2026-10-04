import {
  Action,
  ActionPanel,
  Form,
  Icon,
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
import { addKeysmithAccount, normalizeConfigPath } from "./lib/keysmith";
import { parseOtpUrl } from "./lib/otp";
import { decodeQrImage } from "./lib/qr";

const execFileAsync = promisify(execFile);

function applyOtpUrl(
  raw: string,
  setters: {
    setAccount: (v: string) => void;
    setIssuer: (v: string) => void;
    setSecret: (v: string) => void;
    setType: (v: "totp" | "hotp") => void;
  },
): boolean {
  const url = parseOtpUrl(raw);
  if (!url) return false;
  setters.setAccount(url.account);
  setters.setIssuer(url.issuer);
  setters.setSecret(url.secret);
  setters.setType(url.type);
  return true;
}

async function decodeAndApply(
  imagePath: string,
  setters: {
    setAccount: (v: string) => void;
    setIssuer: (v: string) => void;
    setSecret: (v: string) => void;
    setType: (v: "totp" | "hotp") => void;
  },
): Promise<boolean> {
  const text = await decodeQrImage(imagePath);
  if (!text) {
    await showToast({
      title: "No QR code found",
      message: "Could not find a QR code in that image. Try a clearer screenshot or paste the URL manually.",
      style: Toast.Style.Failure,
    });
    return false;
  }
  if (!applyOtpUrl(text, setters)) {
    await showToast({
      title: "Not an OTP QR code",
      message: "The QR code does not contain an otpauth:// URL.",
      style: Toast.Style.Failure,
    });
    return false;
  }
  await showToast({ title: "QR code detected", message: "Account details filled in. Review and submit." });
  return true;
}

export default function AddAccount() {
  const preferences = getPreferenceValues<ExtensionPreferences>();
  const [account, setAccount] = useState("");
  const [issuer, setIssuer] = useState("");
  const [secret, setSecret] = useState("");
  const [type, setType] = useState<"totp" | "hotp">("totp");

  const setters = { setAccount, setIssuer, setSecret, setType };

  async function handleQrFile(paths: string[]) {
    const file = paths[0];
    if (!file) return;
    try {
      await decodeAndApply(file, setters);
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
      await execFileAsync("spectacle", ["-r", "-b", "-o", output], { timeout: 120000 });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes("ENOENT")) {
        await showToast({
          title: "Spectacle not found",
          message: "Install Spectacle or pick a QR image file instead.",
          style: Toast.Style.Failure,
        });
      } else {
        await showToast({ title: "Screenshot cancelled", message: "No screenshot was captured." });
      }
      return;
    }
    try {
      await decodeAndApply(output, setters);
    } catch (error) {
      await showToast({
        title: "Could not read screenshot",
        message: error instanceof Error ? error.message : String(error),
        style: Toast.Style.Failure,
      });
    }
  }

  async function handleSubmit(values: Record<string, unknown>) {
    const urlValue = String(values.otpUrl ?? "").trim();
    const manualAccount = String(values.account ?? "").trim() || account.trim();
    const manualIssuer = String(values.issuer ?? "").trim() || issuer.trim();
    const manualSecret = String(values.secret ?? "").trim() || secret.trim();
    const manualType = (String(values.type ?? type) as "totp" | "hotp") === "hotp" ? "hotp" : "totp";

    const parsed = urlValue ? parseOtpUrl(urlValue) : null;
    if (urlValue && !parsed) {
      await showToast({
        title: "Invalid otpauth URL",
        message: "Check the URL and try again.",
        style: Toast.Style.Failure,
      });
      return;
    }

    if (!parsed && (!manualAccount || !manualSecret)) {
      await showToast({
        title: "Missing fields",
        message: "Scan a QR code, paste a URL, or enter the account name and secret.",
        style: Toast.Style.Failure,
      });
      return;
    }

    try {
      if (parsed) {
        await addKeysmithAccount(normalizeConfigPath(preferences.configPath), preferences.masterPassword, {
          account: parsed.account,
          issuer: parsed.issuer,
          type: parsed.type,
          hash: parsed.algorithm ? `Sha${parsed.algorithm.replace("SHA", "")}` : "Sha1",
          pinLength: parsed.digits,
          timeStep: parsed.timeStep,
          counter: parsed.counter,
          secret: parsed.secret,
        });
      } else {
        await addKeysmithAccount(normalizeConfigPath(preferences.configPath), preferences.masterPassword, {
          account: manualAccount,
          issuer: manualIssuer,
          type: manualType,
          secret: manualSecret,
        });
      }
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
            title="Capture QR Screenshot"
            icon={Icon.Camera}
            shortcut={{ modifiers: ["cmd", "shift"], key: "s" }}
            onAction={handleScreenshot}
          />
        </ActionPanel>
      }
    >
      <Form.Description text="Scan a QR code, capture it from the screen, paste an otpauth:// URL, or enter the details manually. The account is encrypted into the same Keysmith.conf Keysmith uses." />
      <Form.FilePicker
        id="qrImage"
        title="QR Image"
        allowMultipleSelection={false}
        canChooseDirectories={false}
        onChange={handleQrFile}
      />
      <Form.Description text="Tip: use Capture QR Screenshot from the actions to select a QR code on screen with Spectacle." />
      <Form.Separator />
      <Form.TextField
        id="otpUrl"
        title="otpauth URL"
        placeholder="otpauth://totp/Google:user@example.com?secret=..."
        onChange={(value) => applyOtpUrl(value, setters)}
      />
      <Form.Separator />
      <Form.TextField
        id="account"
        title="Account"
        value={account}
        onChange={setAccount}
        placeholder="Google: user@example.com"
      />
      <Form.TextField
        id="issuer"
        title="Issuer"
        value={issuer}
        onChange={setIssuer}
        placeholder="Google"
      />
      <Form.TextField
        id="secret"
        title="Secret"
        value={secret}
        onChange={setSecret}
        placeholder="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
      />
      <Form.Dropdown id="type" title="Type" value={type} onChange={(value) => setType(value as "totp" | "hotp")}>
        <Form.Dropdown.Item value="totp" title="TOTP" />
        <Form.Dropdown.Item value="hotp" title="HOTP" />
      </Form.Dropdown>
    </Form>
  );
}
