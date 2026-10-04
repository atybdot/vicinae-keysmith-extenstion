#!/usr/bin/env python3
import configparser
import base64
import ctypes
import json
import os
import pathlib
import sys
import time

DEFAULT_CONFIG = os.path.expanduser("~/.config/org.kde.keysmith/Keysmith.conf")


def error(message, code=1):
    json.dump({"error": message}, sys.stderr)
    sys.stderr.write("\n")
    sys.exit(code)


def load_libsodium():
    candidates = [
        "/usr/lib64/libsodium.so.26",
        "/usr/lib/x86_64-linux-gnu/libsodium.so.23",
        "/usr/local/lib/libsodium.so.26",
        "/usr/lib/libsodium.so.26",
    ]
    for path in candidates:
        if os.path.exists(path):
            return ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL)
    try:
        return ctypes.CDLL("libsodium.so.26", mode=ctypes.RTLD_GLOBAL)
    except OSError:
        error("libsodium not found")


def derive_key(lib, password: str, salt: bytes, opslimit: int, memlimit: int, keylen: int):
    out = ctypes.create_string_buffer(keylen)
    lib.crypto_pwhash.restype = ctypes.c_int
    lib.crypto_pwhash.argtypes = [
        ctypes.c_char_p,
        ctypes.c_ulonglong,
        ctypes.c_char_p,
        ctypes.c_ulonglong,
        ctypes.c_char_p,
        ctypes.c_ulonglong,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    rc = lib.crypto_pwhash(
        out,
        keylen,
        password.encode("utf-8"),
        len(password.encode("utf-8")),
        salt,
        opslimit,
        memlimit,
        2,  # crypto_pwhash_ALG_ARGON2ID13
    )
    if rc != 0:
        error("failed to derive key")
    return out.raw


def decrypt_secret(lib, key: bytes, nonce: bytes, ciphertext: bytes):
    out = ctypes.create_string_buffer(max(len(ciphertext) - 16, 1))
    lib.crypto_secretbox_open_easy.restype = ctypes.c_int
    lib.crypto_secretbox_open_easy.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_ulonglong,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    rc = lib.crypto_secretbox_open_easy(out, ciphertext, len(ciphertext), nonce, key)
    if rc != 0:
        error("wrong master password or corrupt Keysmith data")
    return out.raw[: len(ciphertext) - 16]


def load_parser():
    config_path = pathlib.Path(os.environ.get("KEYSMITH_CONFIG", DEFAULT_CONFIG)).expanduser()
    if not config_path.exists():
        error(f"config not found: {config_path}")
    parser = configparser.ConfigParser()
    parser.optionxform = str
    try:
        parser.read(config_path, encoding="utf-8")
    except Exception as exc:
        error(f"failed to read config: {exc}")
    return parser, config_path


def increment_hotp_counter(account_id: str):
    parser, config_path = load_parser()
    if account_id not in parser:
        error("account not found")
    data = parser[account_id]
    if data.get("type") != "hotp":
        error("account is not hotp")
    try:
        counter = int(data.get("counter", "0"))
    except ValueError:
        error("invalid counter")
    data["counter"] = str(counter + 1)
    try:
        with open(config_path, "w", encoding="utf-8") as file:
            parser.write(file)
    except OSError as exc:
        error(f"failed to write config: {exc}")


def main():
    if "--increment-hotp" in sys.argv:
        try:
            index = sys.argv.index("--increment-hotp")
            account_id = sys.argv[index + 1]
        except (IndexError, ValueError):
            error("--increment-hotp requires an account id")
        increment_hotp_counter(account_id)
        return

    config_path = pathlib.Path(os.environ.get("KEYSMITH_CONFIG", DEFAULT_CONFIG)).expanduser()
    password = os.environ.get("KEYSMITH_PASSWORD")
    if not password:
        error("missing keysmith password")
    if not config_path.exists():
        error(f"config not found: {config_path}")

    parser = configparser.ConfigParser()
    parser.optionxform = str
    try:
        parser.read(config_path, encoding="utf-8")
    except Exception as exc:
        error(f"failed to read config: {exc}")

    if "master-key" not in parser:
        error("master-key section not found")

    mk = parser["master-key"]
    try:
        salt = base64.b64decode(mk["salt"].strip('"'))
        opslimit = int(mk["cpu"])
        memlimit = int(mk["memory"])
        keylen = int(mk["length"])
    except Exception as exc:
        error(f"invalid master-key section: {exc}")

    lib = load_libsodium()
    key = derive_key(lib, password, salt, opslimit, memlimit, keylen)

    accounts = []
    for section in parser.sections():
        if section == "master-key":
            continue

        data = parser[section]
        try:
            ciphertext = base64.b64decode(data["secret"])
            nonce = base64.b64decode(data["nonce"])
        except Exception:
            continue

        try:
            raw = decrypt_secret(lib, key, nonce, ciphertext)
        except Exception:
            # showToast will surface a generic failure, skip malformed entries
            continue

        item = {
            "id": section,
            "account": data.get("account", "").strip().strip('"'),
            "issuer": data.get("issuer", "").strip().strip('"'),
            "type": data.get("type", "totp"),
            "hash": data.get("hash", "Sha1"),
            "pinLength": int(data.get("pinLength", "6")),
            "epoch": data.get("epoch", "1970-01-01T00:00:00.000Z"),
            "secretB64": base64.b64encode(raw).decode("ascii"),
        }
        if "timeStep" in data:
            item["timeStep"] = int(data["timeStep"])
        if "counter" in data:
            item["counter"] = int(data["counter"])
        accounts.append(item)

    json.dump(accounts, sys.stdout)


if __name__ == "__main__":
    main()
