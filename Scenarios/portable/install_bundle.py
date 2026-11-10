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
# The next published Thief-Lab bundle had a cleanup command with a fact that
# CALDERA cannot substitute for this ability. Accept only its exact bytes.
THIEF_STAGING_ABILITY_HASHES = {
    "43251ffdfd7b7e49c5d0e7a7899492cf69942facaf4df162f813850486f21f55",  # LF
    "e8fd455a622e291e7f8bae1a9c508ca70a20df720eb62cd34db5d9608542635c",  # CRLF
}
# Accept the published Git bytes (LF) and Windows checkout bytes (CRLF).
DISCOVERY_PROFILE_HASHES = {
    "6ba32f690d2915ffc4301f07d8f60569046d58392c0f287a92a561914c12728e",
    "ede1dbb3504abefe1fd3ebc97d3e0bf05ab49b9604d61641fe3ac962a2dbee74",
}
OLD_DEFENDER_ABILITY = "d8dbc446fea6514a712803194b10cb75.yml"
OLD_DEFENDER_HASHES = {
    "820fe3b093ef89ef614cfff03a150e307d886ee3232874d1fc4f7dcf12133b1a",
    "5f8a7cbb025e6f51324c23a4f595036567e97d620fe1656eaf70055fa1e2b976",
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
    obsolete = root / "data" / "abilities" / "discovery" / OLD_DEFENDER_ABILITY
    remove_obsolete = False
    if upgrade and obsolete.exists():
        if obsolete.is_file() and hashlib.sha256(obsolete.read_bytes()).hexdigest() in OLD_DEFENDER_HASHES:
            remove_obsolete = True
        else:
            conflicts.append(obsolete)
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
        current_hash = hashlib.sha256(current_bytes).hexdigest()
        published_profile = destination.name == "c6946236-d4e4-4e4f-8dc7-433c84a702a3.yml" and current_hash in DISCOVERY_PROFILE_HASHES
        published_thief_ability = (destination.name == "0ae51c4e-c546-469d-bdf9-0ace34556391.yml"
                                   and current_hash in THIEF_STAGING_ABILITY_HASHES)
        if upgrade and ((previous_hash and current_hash == previous_hash)
                        or published_profile or published_thief_ability):
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
    if remove_obsolete:
        obsolete.unlink()
    noun = "file" if copied == 1 else "files"
    print(f"Installed {copied} {noun}; updated {replaced} known earlier bundle files; removed {int(remove_obsolete)} obsolete Defender ability; {matched} already matched. Restart CALDERA and verify the five profiles.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caldera-root", required=True, type=Path, help="CALDERA checkout, for example ~/caldera")
    parser.add_argument("--upgrade", action="store_true", help="Replace only known files from the first bundle release")
    args = parser.parse_args()
    install(args.caldera_root, upgrade=args.upgrade)
