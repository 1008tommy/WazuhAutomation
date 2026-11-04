"""Install the portable scenario bundle into a local CALDERA checkout.

Run on the CALDERA server. Existing files are never overwritten.
"""

import argparse
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCENARIOS = HERE.parent


def install(caldera_root):
    root = caldera_root.expanduser().resolve()
    if not (root / "app").is_dir():
        raise SystemExit(f"Not a CALDERA checkout: {root}")
    if not (root / "plugins" / "stockpile" / "hook.py").is_file():
        raise SystemExit(
            f"Stockpile is missing from {root / 'plugins' / 'stockpile'}. "
            "If this is a Git checkout, run 'git submodule update --init plugins/stockpile' "
            "from the CALDERA root, then ensure stockpile is enabled in the active config."
        )

    ability_files = sorted((HERE / "abilities").rglob("*.yml"))
    adversary_files = sorted((HERE / "adversaries").glob("*.yml"))
    payload = SCENARIOS / "required-payloads" / "lab-note.ps1"
    if len(ability_files) != 9 or len(adversary_files) != 4 or not payload.is_file():
        raise SystemExit("Bundle is incomplete; check that the correct branch was cloned")

    transfers = [
        (path, root / "data" / "abilities" / path.relative_to(HERE / "abilities"))
        for path in ability_files
    ]
    transfers += [(path, root / "data" / "adversaries" / path.name) for path in adversary_files]
    transfers.append((payload, root / "plugins" / "stockpile" / "payloads" / payload.name))

    conflicts = [
        destination for source, destination in transfers
        if destination.exists() and (not destination.is_file() or destination.read_bytes() != source.read_bytes())
    ]
    if conflicts:
        details = "\n".join(str(path) for path in conflicts)
        raise SystemExit(f"Existing files differ; nothing copied. Compare these files first:\n{details}")

    copied = 0
    for source, destination in transfers:
        if destination.exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied += 1
    print(f"Installed {copied} files; {len(transfers) - copied} already matched. Restart CALDERA and verify the four profiles.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caldera-root", required=True, type=Path, help="CALDERA checkout, for example ~/caldera")
    args = parser.parse_args()
    install(args.caldera_root)
