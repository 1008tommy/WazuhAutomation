"""Install the portable scenario bundle into a local CALDERA checkout.

Run on the CALDERA server. Existing files are never overwritten.
"""

import argparse
import hashlib
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCENARIOS = HERE.parent

# The first published bundle used a list for executor parsers. CALDERA 5.3.0
# requires a mapping. These hashes permit replacing only those exact files.
PREVIOUS_ABILITY_HASHES = {
    "0ae51c4e-c546-469d-bdf9-0ace34556391.yml": "75007e2245d82742de9cb51c1f954f0cdb565c6692aeb9f691c10f032222cc42",
    "1fd8b672-e336-49eb-86bc-8731368b451d.yml": "2f2df8d83419c757c3a29a6bcf89991643fe6bad439a7b61f86ecbc0b473e242",
    "50a40429-7a61-4a76-b8ff-600f3e7f8bff.yml": "6d15ea3420a3e83bece9df34d45cfc3efc04e49bcfd17b0269a8aa6a4d34931e",
    "72afaf5a-b793-4301-a791-8dff54918e4e.yml": "cf6a9f1f68ccbc489b64348bc0e386bda6fb4c5c14c0b3322d8b2d23baa993fb",
}


def install(caldera_root, upgrade=False):
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
    source_files = sorted((HERE / "sources").glob("*.yml"))
    payload = SCENARIOS / "required-payloads" / "lab-note.ps1"
    if len(ability_files) != 15 or len(adversary_files) != 5 or len(source_files) != 1 or not payload.is_file():
        raise SystemExit("Bundle is incomplete; check that the correct branch was cloned")

    transfers = [
        (path, root / "data" / "abilities" / path.relative_to(HERE / "abilities"))
        for path in ability_files
    ]
    transfers += [(path, root / "data" / "adversaries" / path.name) for path in adversary_files]
    transfers += [(path, root / "data" / "sources" / path.name) for path in source_files]
    transfers.append((payload, root / "plugins" / "stockpile" / "payloads" / payload.name))

    conflicts = []
    replacements = set()
    for source, destination in transfers:
        if not destination.exists():
            continue
        if not destination.is_file():
            conflicts.append(destination)
            continue
        current_bytes = destination.read_bytes()
        if current_bytes == source.read_bytes():
            continue
        previous_hash = PREVIOUS_ABILITY_HASHES.get(destination.name)
        if upgrade and previous_hash and hashlib.sha256(current_bytes).hexdigest() == previous_hash:
            replacements.add(destination)
        else:
            conflicts.append(destination)
    if conflicts:
        details = "\n".join(str(path) for path in conflicts)
        raise SystemExit(f"Existing files differ; nothing copied. Compare these files first:\n{details}")

    copied = 0
    replaced = 0
    for source, destination in transfers:
        if destination in replacements:
            shutil.copy2(source, destination)
            replaced += 1
            continue
        if destination.exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied += 1
    matched = len(transfers) - copied - replaced
    noun = "file" if copied == 1 else "files"
    print(f"Installed {copied} {noun}; updated {replaced} known earlier bundle files; {matched} already matched. Restart CALDERA and verify the five profiles.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caldera-root", required=True, type=Path, help="CALDERA checkout, for example ~/caldera")
    parser.add_argument("--upgrade", action="store_true", help="Replace only known files from the first bundle release")
    args = parser.parse_args()
    install(args.caldera_root, upgrade=args.upgrade)
