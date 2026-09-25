"""Install the pinned local media decoder without changing system packages."""
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
DEPENDENCIES = ROOT / "work" / "media-deps"
VERSION = "18.1.0"
# Verified against https://pypi.org/pypi/av/18.1.0/json.
# CPython >=3.11 stable ABI, manylinux 2.28, x86_64.
WHEEL_SHA256 = "8a032e8d8ebc73dec079364b9b4a6837638a2d106e8472314e685ffbf163e700"


def main():
    (ROOT / "work").mkdir(parents=True, exist_ok=True)
    DEPENDENCIES.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="media-install-", dir=ROOT / "work") as temp:
        requirements = Path(temp) / "requirements.txt"
        requirements.write_text(f"av=={VERSION} --hash=sha256:{WHEEL_SHA256}\n", encoding="utf-8")
        subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--only-binary=:all:",
                        "--no-deps", "--require-hashes", "--upgrade", "--target", str(DEPENDENCIES),
                        "--index-url", "https://pypi.org/simple", "-r", str(requirements)], check=True)
    print(f"Installed pinned PyAV {VERSION} into {DEPENDENCIES}")


if __name__ == "__main__":
    main()
