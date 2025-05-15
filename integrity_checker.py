import os
import hashlib
import json
from pathlib import Path

HASH_STORE = Path(".integrity_db.json")

def compute_hash(filepath: Path) -> str:
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return f"ERROR: {e}"

def scan_directory(directory: str) -> dict:
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            path = Path(root) / file
            hash_val = compute_hash(path)
            file_hashes[str(path)] = hash_val
    return file_hashes

def save_hashes(hashes: dict):
    with open(HASH_STORE, "w") as f:
        json.dump(hashes, f, indent=2)

def load_hashes() -> dict:
    if not HASH_STORE.exists():
        return {}
    with open(HASH_STORE, "r") as f:
        return json.load(f)

def run(mode: str, directory: str):
    print(f"Integrity checker running in '{mode}' mode on: {directory}")
    if mode == "scan":
        hashes = scan_directory(directory)
        save_hashes(hashes)
        print(f"✅ Scan complete. Hashes saved to {HASH_STORE}")
    elif mode == "verify":
        old_hashes = load_hashes()
        new_hashes = scan_directory(directory)
        modified = []

        for path, new_hash in new_hashes.items():
            old_hash = old_hashes.get(path)
            if old_hash is None:
                print(f"[+] New file detected: {path}")
            elif old_hash != new_hash:
                print(f"[!] Modified: {path}")

        for path in old_hashes:
            if path not in new_hashes:
                print(f"[x] Deleted: {path}")
    else:
        print("Invalid mode. Use 'scan' or 'verify'.")
