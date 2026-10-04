# Keysmith for Vicinae

A small Vicinae extension that lists your Keysmith OTP accounts, lets you search them, and copies the current code.

## Features

- Search Keysmith accounts by account name or issuer.
- Generate TOTP codes with live countdown.
- Copy the current code with the built-in copy action.
- For HOTP, copy and increment the account counter.
- Red countdown when fewer than 10 seconds remain.
- Reads the same `Keysmith.conf` file used by the KDE application.

## Development setup

```bash
npm install
npm run dev
```

Other useful scripts:

```bash
npm run typecheck
npm run lint
npm run format
npm run build
```

## Configuration

When you open the extension, Vicinae asks for:

- `Master password`: your Keysmith master password.
- `Config path`: your `Keysmith.conf` path.

Default config path:

```text
~/.config/org.kde.keysmith/Keysmith.conf
```

## Notes

- This extension runs the decryption and OTP calculation locally.
- Your Keysmith master password is stored in Vicinae's extension preferences.
- For HOTP accounts, use the "Use Code and Increment" action. It updates `Keysmith.conf` before the next code is generated.
- Vicinae extensions expose the extension command in root search. Open the Keysmith command first, then search inside its list.

## Why Python?

Keysmith uses libsodium and Argon2id to protect OTP secrets. Python 3 with a small libsodium helper is the least friction way to reproduce that without porting the exact Keysmith crypto path into TypeScript.
