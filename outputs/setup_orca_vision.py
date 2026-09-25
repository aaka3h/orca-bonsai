#!/usr/bin/env python3
"""Download Orca's pinned local vision weights; no account or API key is needed."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

WORKSPACE = Path(__file__).resolve().parent.parent
DEFAULT_MODELS_DIR = WORKSPACE / "work" / "vision-models"
REPOSITORY = "Qwen/Qwen3-VL-2B-Instruct-GGUF"
REVISION = "52d6c8ffea26cc873ac5ad116f8631268d7eb503"
MODEL_NAME = "Qwen3-VL-2B-Instruct"
MODEL_FILE = "Qwen3VL-2B-Instruct-Q4_K_M.gguf"
PROJECTOR_FILE = "mmproj-Qwen3VL-2B-Instruct-Q8_0.gguf"
FILES = {
    MODEL_FILE: {
        "size": 1107409952,
        "sha256": "089d75c52f4b7ffc56ba998ffc50aae89fcafc755f9e7208aacca281dca6c2ae",
    },
    PROJECTOR_FILE: {
        "size": 445053216,
        "sha256": "f9a68fabba69c3b81e153367b2c7521030b0fa8bb0de400c9599c8e6725f9c82",
    },
}


def verify_file(path: Path, expected: dict) -> bool:
    if not path.is_file() or path.stat().st_size != expected["size"]:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest() == expected["sha256"]


def _download(directory: Path, name: str, expected: dict) -> None:
    target = directory / name
    if verify_file(target, expected):
        print(f"Verified {name}", flush=True)
        return
    partial = directory / (name + ".part")
    url = f"https://huggingface.co/{REPOSITORY}/resolve/{REVISION}/{name}"
    for attempt in range(3):
        offset = partial.stat().st_size if partial.exists() else 0
        if offset >= expected["size"]:
            if verify_file(partial, expected):
                os.replace(partial, target)
                return
            partial.unlink()
            offset = 0
        request = urllib.request.Request(url, headers={"User-Agent": "Orca-Local-Vision/1.0"})
        if offset:
            request.add_header("Range", f"bytes={offset}-")
        print(f"Downloading {name} ({expected['size'] / 1e6:.0f} MB)", flush=True)
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                if offset and response.status == 206:
                    if not response.headers.get("Content-Range", "").startswith(f"bytes {offset}-"):
                        raise ValueError("The download server returned an invalid byte range")
                    mode = "ab"
                else:
                    offset = 0
                    mode = "wb"
                last_progress = time.monotonic()
                with partial.open(mode) as output:
                    os.chmod(partial, 0o600)
                    while True:
                        chunk = response.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        offset += len(chunk)
                        if offset > expected["size"]:
                            raise ValueError("The downloaded file exceeds its pinned size")
                        output.write(chunk)
                        if time.monotonic() - last_progress >= 10:
                            print(f"  {offset / expected['size']:.0%}", flush=True)
                            last_progress = time.monotonic()
                    output.flush()
                    os.fsync(output.fileno())
            if not verify_file(partial, expected):
                partial.unlink(missing_ok=True)
                raise ValueError("The download failed its pinned SHA256 integrity check")
            os.replace(partial, target)
            print(f"Verified {name}", flush=True)
            return
        except (OSError, ValueError, urllib.error.URLError) as exc:
            if attempt == 2:
                raise RuntimeError(f"Could not download {name}: {type(exc).__name__}") from exc
            print("Download interrupted; retrying the verified source…", flush=True)
            time.sleep(1 + attempt)


def setup(models_dir: Path = DEFAULT_MODELS_DIR, *, check_only: bool = False) -> dict:
    models_dir = models_dir.expanduser().resolve()
    models_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (models_dir / ".setup.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if check_only:
            valid = {name: verify_file(models_dir / name, expected) for name, expected in FILES.items()}
            if not all(valid.values()):
                missing = ", ".join(name for name, verified in valid.items() if not verified)
                raise RuntimeError(f"Missing or invalid vision files: {missing}")
        else:
            for name, expected in FILES.items():
                _download(models_dir, name, expected)
        manifest = {
            "model": MODEL_NAME,
            "repository": REPOSITORY,
            "revision": REVISION,
            "source": f"https://huggingface.co/{REPOSITORY}/tree/{REVISION}",
            "license": "Apache-2.0",
            "files": FILES,
            "verified_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        temp_manifest = models_dir / "manifest.json.tmp"
        temp_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.chmod(temp_manifest, 0o600)
        os.replace(temp_manifest, models_dir / "manifest.json")
        return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-dir", type=Path,
                        default=Path(os.environ.get("ORCA_VISION_MODELS_DIR", DEFAULT_MODELS_DIR)))
    parser.add_argument("--check", action="store_true", help="Check existing files without downloading")
    args = parser.parse_args()
    try:
        setup(args.models_dir, check_only=args.check)
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Local vision model ready in {args.models_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
