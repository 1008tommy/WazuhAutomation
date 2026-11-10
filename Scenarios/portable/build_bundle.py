"""Build CALDERA server data files from the versioned adversary exports.

Requires PyYAML. The UI exports omit parser, cleanup, and requirement settings;
this script adds the known settings in EXTRAS. Review changes against the source
CALDERA server before treating the bundle as an exact backup.
"""

from pathlib import Path
import re
import yaml

SCENARIOS = Path(__file__).resolve().parents[1]
ROOT = Path(__file__).resolve().parent
THIEF_SOURCE_ID = "94ec2647-e6f5-468d-93a5-557e3671b97a"
EXPORTS = (
    "Scheduled Task Creation.yaml",
    "Renamed Utility Lab.yaml",
    "File Delivery and Execution Lab.yaml",
    "Thief-Lab.yaml",
    "Discovery Scenario.yaml",
)
STOCKPILE_IDS = {
    "300157e5-f4ad-4569-b533-9d1fa0e74d74",  # Compress staged directory
    "ea713bc4-63f0-491c-9a6f-0b01d560b87e",  # Exfil staged directory
}
# Keep the exported profile as a record of the tested run, but give the
# parser-free Defender variant its own ID in the portable installation.
CLONED_IDS = {
    "d8dbc446fea6514a712803194b10cb75": "84ec1290-e830-4ae2-b7b6-16adc609c23d",
}
EXTRAS = {
    "f0bb5f01-c06c-4f8e-8a27-475842661906": {
        "cleanup": "schtasks.exe /Query /TN 'CALDERA-Lab-Test' *> $null; if ($LASTEXITCODE -eq 0) { schtasks.exe /Delete /TN 'CALDERA-Lab-Test' /F; if ($LASTEXITCODE -ne 0) { throw 'Scheduled task deletion failed' } }; $marker='C:\\BASLab\\task-executed'; if (Test-Path -LiteralPath $marker -PathType Container) { [System.IO.Directory]::Delete($marker) }"
    },
    "1ff3f71b-ccc1-4f39-8045-0dbb8359e6b0": {
        "cleanup": "$dir='C:\\BASLab\\masquerade-test'; $file=Join-Path $dir 'lab-helper.exe'; if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file -Force -ErrorAction Stop }; if (Test-Path -LiteralPath $dir -PathType Container) { [System.IO.Directory]::Delete($dir) }"
    },
    "72afaf5a-b793-4301-a791-8dff54918e4e": {
        "cleanup": "$dir='C:\\BASLab\\delivery-test'; foreach($name in @('executed.marker','lab-note.ps1')) { $file=Join-Path $dir $name; if ([System.IO.File]::Exists($file)) { [System.IO.File]::Delete($file) } }; if ([System.IO.Directory]::Exists($dir) -and -not (Get-ChildItem -LiteralPath $dir -Force)) { [System.IO.Directory]::Delete($dir) }",
        "parser": "host.file.downloaded",
    },
    # CALDERA builds cleanup from facts used by this ability's command. This
    # command uses no extension fact, so its cleanup must not reference one.
    "0ae51c4e-c546-469d-bdf9-0ace34556391": {
        "cleanup": (
            "$dir='C:\\BASLab\\staged'; $archive='C:\\BASLab\\staged.zip'; "
            "if (Test-Path -LiteralPath $dir -PathType Container) { "
            "$items=@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop); "
            "if ($items.Count -gt 1 -or ($items.Count -eq 1 -and $items[0].PSIsContainer)) "
            "{ throw 'Unexpected items in BAS staging directory' }; "
            "if ($items.Count -eq 1) { Remove-Item -LiteralPath $items[0].FullName -Force -ErrorAction Stop }; "
            "[System.IO.Directory]::Delete($dir) }; "
            "if (Test-Path -LiteralPath $archive -PathType Leaf) "
            "{ Remove-Item -LiteralPath $archive -Force -ErrorAction Stop }"
        ),
        "parser": "host.dir.staged",
    },
    "1fd8b672-e336-49eb-86bc-8731368b451d": {"parser": "host.file.path"},
    "50a40429-7a61-4a76-b8ff-600f3e7f8bff": {
        "requirements": ["host.file.path", "host.dir.staged"]
    },
}


def write_yaml(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False, allow_unicode=True), encoding="utf-8")


def build():
    write_yaml(
        ROOT / "sources" / f"{THIEF_SOURCE_ID}.yml",
        {
            "id": THIEF_SOURCE_ID,
            "name": "Thief-Lab",
            "facts": [{"trait": "file.sensitive.extension", "value": "txt", "score": 11}],
            "rules": [],
            "relationships": [],
        },
    )
    all_ids = set()
    custom_ids = set()
    for filename in EXPORTS:
        exported = yaml.safe_load((SCENARIOS / filename).read_text(encoding="utf-8"))
        profile = {key: exported[key] for key in ("id", "name", "description", "objective", "atomic_ordering")}
        profile["atomic_ordering"] = [CLONED_IDS.get(ability_id, ability_id) for ability_id in profile["atomic_ordering"]]
        write_yaml(ROOT / "adversaries" / f"{profile['id']}.yml", profile)
        for ability_id in exported["atomic_ordering"]:
            if ability_id in all_ids:
                raise ValueError(f"Duplicate ability ID: {ability_id}")
            all_ids.add(ability_id)
            if ability_id in STOCKPILE_IDS:
                continue
            details = exported["abilities"][ability_id]
            executors = [entry for entry in details["executors"] if entry.get("platform") == "windows"]
            if len(executors) != 1:
                raise ValueError(f"Expected one Windows executor for {ability_id}")
            executor_names = [name for name in ("psh", "cmd") if name in executors[0]]
            if len(executor_names) != 1:
                raise ValueError(f"Expected one Windows psh or cmd executor for {ability_id}")
            executor_name = executor_names[0]
            command = executors[0]["command"]
            if ability_id == "72afaf5a-b793-4301-a791-8dff54918e4e":
                command, replacements = re.subn(r"https?://[^/\s'\"]+/file/download", "#{server}/file/download", command, count=1)
                if replacements != 1:
                    raise ValueError("Expected one CALDERA file-download URL")
            executor = {"command": command, "timeout": 60}
            extras = EXTRAS.get(ability_id, {})
            if "cleanup" in extras:
                executor["cleanup"] = extras["cleanup"]
            if "parser" in extras:
                executor["parsers"] = {"plugins.stockpile.app.parsers.basic": [{"source": extras["parser"]}]}
            portable_id = CLONED_IDS.get(ability_id, ability_id)
            ability = {
                "id": portable_id,
                "name": "Lab Windows Defender Enumeration" if ability_id in CLONED_IDS else details["name"],
                "description": f"Windows BAS lab ability for {profile['name']}",
                "tactic": details["tactic"],
                "technique": {"attack_id": details["technique_id"], "name": details["technique_name"]},
                "platforms": {"windows": {executor_name: executor}},
            }
            if "requirements" in extras:
                ability["requirements"] = [
                    {"plugins.stockpile.app.requirements.paw_provenance": [{"source": source}]}
                    for source in extras["requirements"]
                ]
            write_yaml(ROOT / "abilities" / details["tactic"] / f"{portable_id}.yml", [ability])
            custom_ids.add(portable_id)
    assert len(all_ids) == 17 and len(custom_ids) == 15
    print(f"Built {len(custom_ids)} custom abilities, {len(EXPORTS)} adversaries, and 1 fact source")


if __name__ == "__main__":
    build()
