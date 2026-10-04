"""Download an Ollama model with curl and install it into Ollama's models folder.

Use this when `ollama pull` fails (e.g. "unexpected EOF") but curl works.

    py ollama_manual_pull.py                    # llama3.2:3b
    py ollama_manual_pull.py llama3.2 3b        # same thing, explicit

Downloads are resumable: if it stops, just run the script again.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

CURL = "curl.exe" if os.name == "nt" else "curl"
MAX_ROUNDS = 30


def curl(args):
    cmd = [CURL, "-4", "-L", "--fail", "--retry", "20", "--retry-all-errors",
           "--retry-delay", "3", *args]
    return subprocess.run(cmd).returncode


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def blob_ok(path, layer):
    hex_digest = layer["digest"].split(":", 1)[1]
    return (path.exists() and path.stat().st_size == layer["size"]
            and sha256_of(path) == hex_digest)


def download_layer(url, layer, blobs_dir):
    hex_digest = layer["digest"].split(":", 1)[1]
    final = blobs_dir / f"sha256-{hex_digest}"
    partial = blobs_dir / f"sha256-{hex_digest}.partial"
    size_mb = layer["size"] / 1_000_000

    if blob_ok(final, layer):
        print(f"  already complete: {final.name[:20]}... ({size_mb:.1f} MB)")
        return True

    print(f"  downloading {final.name[:20]}... ({size_mb:.1f} MB)")
    for round_number in range(1, MAX_ROUNDS + 1):
        curl(["--progress-bar", "-C", "-", "-o", str(partial), f"{url}/blobs/{layer['digest']}"])
        if partial.exists() and partial.stat().st_size == layer["size"]:
            break
        have = partial.stat().st_size / 1_000_000 if partial.exists() else 0
        print(f"  incomplete ({have:.1f}/{size_mb:.1f} MB), retrying "
              f"({round_number}/{MAX_ROUNDS})...")
    else:
        print("  giving up for now; run the script again to resume.")
        return False

    if sha256_of(partial) != hex_digest:
        print("  checksum mismatch, deleting the partial file; run again.")
        partial.unlink()
        return False
    partial.replace(final)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("model", nargs="?", default="llama3.2")
    parser.add_argument("tag", nargs="?", default="3b")
    parser.add_argument("--registry", default="https://registry.ollama.ai")
    parser.add_argument("--models-dir", default=None)
    args = parser.parse_args()

    models_dir = Path(args.models_dir or os.environ.get("OLLAMA_MODELS")
                      or Path.home() / ".ollama" / "models")
    blobs_dir = models_dir / "blobs"
    manifest_path = (models_dir / "manifests" / "registry.ollama.ai" / "library"
                     / args.model / args.tag)
    blobs_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    url = f"{args.registry}/v2/library/{args.model}"

    print(f"Models folder: {models_dir}")
    print("Fetching manifest...")
    tmp_manifest = blobs_dir / "manifest.download"
    code = curl(["-sS", "-H", "Accept: application/vnd.docker.distribution.manifest.v2+json",
                 "-o", str(tmp_manifest), f"{url}/manifests/{args.tag}"])
    if code != 0 or not tmp_manifest.exists():
        print("Could not fetch the manifest. Check the model name/tag and your connection.")
        return 1
    raw_manifest = tmp_manifest.read_bytes()
    tmp_manifest.unlink()
    manifest = json.loads(raw_manifest)

    layers = [manifest["config"]] + manifest["layers"]
    total_mb = sum(layer["size"] for layer in layers) / 1_000_000
    print(f"{len(layers)} files, {total_mb:.0f} MB in total.")

    for layer in layers:
        if not download_layer(url, layer, blobs_dir):
            return 1

    manifest_path.write_bytes(raw_manifest)
    print(f"\nDone. Now run:  ollama list   (you should see {args.model}:{args.tag})")
    return 0


if __name__ == "__main__":
    sys.exit(main())