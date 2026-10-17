import { Action, ActionPanel, Form, Icon } from "@vicinae/api";
import { useRef, useState } from "react";
import {
  DEFAULT_LOCK_POLICY,
  LOCK_POLICIES,
  type LockPolicy,
  type UnlockResult,
} from "../lib/vault";

type UnlockFormProps = {
  /** First run asks for the lock policy as well as the password. */
  firstRun: boolean;
  /** Prefilled from the old master password preference during migration. */
  defaultPassword?: string;
  onSubmit: (password: string, policy: LockPolicy) => Promise<UnlockResult>;
};

export function UnlockForm({ firstRun, defaultPassword = "", onSubmit }: UnlockFormProps) {
  const [password, setPassword] = useState(defaultPassword);
  const [policy, setPolicy] = useState<LockPolicy>(DEFAULT_LOCK_POLICY);
  const [error, setError] = useState<string | undefined>();
  const [submitting, setSubmitting] = useState(false);
  const passwordRef = useRef<Form.PasswordField>(null);

  async function handleSubmit() {
    if (!password) {
      setError("Enter your Keysmith master password.");
      return;
    }
    setSubmitting(true);
    setError(undefined);
    try {
      const result = await onSubmit(password, policy);
      if (!result.ok) {
        // Keep the form mounted so the user can retry with the right password.
        setError(result.message);
        setPassword("");
        passwordRef.current?.reset();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  }

  const selectedPolicy = LOCK_POLICIES.find((entry) => entry.value === policy);

  return (
    <Form
      isLoading={submitting}
      navigationTitle={firstRun ? "Unlock Keysmith" : "Keysmith locked"}
      actions={
        <ActionPanel>
          <Action.SubmitForm
            title={firstRun ? "Unlock and Continue" : "Unlock"}
            icon={Icon.LockUnlocked}
            onSubmit={handleSubmit}
          />
          {firstRun ? (
            <ActionPanel.Section title="Lock policy">
              {LOCK_POLICIES.map((entry) => (
                <Action
                  key={entry.value}
                  title={entry.title}
                  icon={entry.value === policy ? Icon.CheckCircle : Icon.Circle}
                  onAction={() => setPolicy(entry.value)}
                />
              ))}
            </ActionPanel.Section>
          ) : null}
        </ActionPanel>
      }
    >
      <Form.Description
        title={firstRun ? "Welcome to Keysmith" : "Vault locked"}
        text={
          firstRun
            ? "Enter the master password you use in Keysmith. The password itself is never stored, but a key derived from it can be cached according to the policy below."
            : "Enter your Keysmith master password to unlock the vault."
        }
      />
      <Form.PasswordField
        id="password"
        title="Master password"
        value={password}
        onChange={(value) => {
          setPassword(value);
          if (error) setError(undefined);
        }}
        error={error}
        autoFocus
        ref={passwordRef}
      />
      {firstRun ? (
        <Form.Description
          title={selectedPolicy ? `Lock policy: ${selectedPolicy.title}` : "Lock policy"}
          text={
            selectedPolicy
              ? `${selectedPolicy.description} Change it from the action panel.`
              : "Change it from the action panel."
          }
        />
      ) : null}
    </Form>
  );
}
