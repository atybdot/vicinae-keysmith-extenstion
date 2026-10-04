# Keysmith for Vicinae

A Vicinae extension that reads your KDE Keysmith OTP store directly. Search accounts, copy the current TOTP or HOTP code, and add new accounts without managing a second OTP database.

## Commands

- **Search OTP Codes**: searchable list of Keysmith accounts with live codes. TOTP rows show a countdown that turns red under 10 seconds. HOTP rows offer a "Use Code and Increment" action.
- **Add Account**: paste an `otpauth://` URL to auto-fill the form, or enter the account details manually. The account is encrypted and appended to the same `Keysmith.conf` Keysmith uses.

## Features

- Search Keysmith accounts by account name or issuer.
- TOTP codes with live countdown, HOTP codes with counter tracking.
- Brand icons for common issuers, bundled from the Simple Icons project (CC0 1.0).
- No subprocesses, no network access. Everything runs locally.

## Requirements

- Linux with KDE Keysmith installed and configured.
- Node.js 20 or newer, `npm` for installing dependencies.

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

This project uses oxlint and oxfmt. The committed `package-lock.json` is generated with `npm install` and is required for store submission.

## Configuration

When you open the extension, Vicinae asks for:

- `Master password`: your Keysmith master password.
- `Config path`: your `Keysmith.conf` path.

Default config path:

```text
~/.config/org.kde.keysmith/Keysmith.conf
```

## Privacy and security

- Decryption (Argon2id key derivation plus secretbox) and OTP calculation happen locally on your machine.
- Your Keysmith master password lives in Vicinae's extension preferences, alongside your other extension settings.
- OTP secrets are held in memory only while the command view is open.
- Adding an account or incrementing an HOTP counter rewrites `Keysmith.conf` atomically through a temporary file plus rename.
- If the master password is wrong, decryption fails and the extension shows an error instead of an empty list.

## Notes

- Vicinae extensions expose the extension command in root search. Open the Keysmith command first, then search inside its list.
- Brand icons are a small bundled set for v1. Dynamic icon fetching is a possible future improvement.

## How it works

Keysmith stores each OTP secret encrypted with libsodium `crypto_secretbox`, using a key derived from the master password with Argon2id. The parameters live in the `master-key` section of `Keysmith.conf`. This extension reimplements that read path with `libsodium-wrappers-sumo` (the sumo build is required because `crypto_pwhash` is excluded from the standard build) and computes TOTP and HOTP codes locally.
