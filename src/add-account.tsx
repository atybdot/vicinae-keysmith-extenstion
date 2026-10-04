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
import { useEffect, useState } from "react";
import { addKeysmithAccount, normalizeConfigPath } from "./lib/keysmith";
import { parseOtpUrl } from "./lib/otp";

export default function AddAccount() {
  const preferences = getPreferenceValues<ExtensionPreferences>();
  const [otpUrl, setOtpUrl] = useState("");
  const [account, setAccount] = useState("");
  const [issuer, setIssuer] = useState("");
  const [secret, setSecret] = useState("");
  const [type, setType] = useState<"totp" | "hotp">("totp");

  useEffect(() => {
    const url = parseOtpUrl(otpUrl);
    if (url) {
      setAccount(url.account);
      setIssuer(url.issuer);
      setSecret(url.secret);
      setType(url.type);
    }
  }, [otpUrl]);

  async function handleSubmit(values: Record<string, unknown>) {
    const urlValue = String(values.otpUrl ?? "").trim();
    const manualAccount = String(values.account ?? "").trim();
    const manualIssuer = String(values.issuer ?? "").trim();
    const manualSecret = String(values.secret ?? "").trim();
    const manualType = String(values.type ?? "totp") as "totp" | "hotp";

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
        message: "Enter both the account name and the OTP secret.",
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
      await showToast({
        title: "Account added",
        message: `${type.toUpperCase()} account was added to Keysmith.`,
      });
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
        </ActionPanel>
      }
    >
      <Form.Description text="Paste an otpauth:// URL or enter the account details manually." />
      <Form.TextField
        id="otpUrl"
        title="otpauth URL"
        value={otpUrl}
        onChange={setOtpUrl}
        placeholder="otpauth://totp/Google:user@example.com?secret=..."
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
