"""Validate the portable CALDERA bundle without contacting a server."""

from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent
STOCKPILE_IDS = {
    "300157e5-f4ad-4569-b533-9d1fa0e74d74",
    "ea713bc4-63f0-491c-9a6f-0b01d560b87e",
}
PARSERS = {
    "0ae51c4e-c546-469d-bdf9-0ace34556391": "host.dir.staged",
    "1fd8b672-e336-49eb-86bc-8731368b451d": "host.file.path",
    "72afaf5a-b793-4301-a791-8dff54918e4e": "host.file.downloaded",
}
CLEANUP = {
    "0ae51c4e-c546-469d-bdf9-0ace34556391",
    "f0bb5f01-c06c-4f8e-8a27-475842661906",
    "1ff3f71b-ccc1-4f39-8045-0dbb8359e6b0",
    "72afaf5a-b793-4301-a791-8dff54918e4e",
}


def check():
    abilities = {}
    for path in (ROOT / "abilities").rglob("*.yml"):
        entries = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(entries, list) and len(entries) == 1, path
        ability = entries[0]
        ability_id = ability["id"]
        assert ability_id == path.stem and ability_id not in abilities, path
        assert path.parent.name == ability["tactic"], path
        executors = ability["platforms"]["windows"]
        assert len(executors) == 1 and next(iter(executors)) in {"psh", "cmd"}, path
        executor = next(iter(executors.values()))
        assert executor["command"].strip(), path
        assert ability["technique"]["attack_id"], path
        if ability_id in CLEANUP:
            assert executor["cleanup"].strip(), path
        if ability_id in PARSERS:
            assert executor["parsers"]["plugins.stockpile.app.parsers.basic"][0]["source"] == PARSERS[ability_id], path
        if ability_id == "84ec1290-e830-4ae2-b7b6-16adc609c23d":
            assert "parsers" not in executor, path
        if ability_id == "50a40429-7a61-4a76-b8ff-600f3e7f8bff":
            assert "requirements" not in executor, path
            sources = [entry["plugins.stockpile.app.requirements.paw_provenance"][0]["source"] for entry in ability["requirements"]]
            assert sources == ["host.file.path", "host.dir.staged"], path
        abilities[ability_id] = ability
    profiles = []
    referenced = set()
    for path in (ROOT / "adversaries").glob("*.yml"):
        profile = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert profile["id"] == path.stem, path
        assert profile["atomic_ordering"], path
        assert len(profile["atomic_ordering"]) == len(set(profile["atomic_ordering"])), path
        referenced.update(profile["atomic_ordering"])
        profiles.append(profile)
    assert len(profiles) == 5, len(profiles)
    assert len(abilities) == 15, len(abilities)
    assert "d8dbc446fea6514a712803194b10cb75" not in referenced | set(abilities)
    assert "84ec1290-e830-4ae2-b7b6-16adc609c23d" in referenced & set(abilities)
    assert referenced == set(abilities) | STOCKPILE_IDS, sorted(referenced ^ (set(abilities) | STOCKPILE_IDS))
    assert (ROOT.parent / "required-payloads" / "lab-note.ps1").is_file()
    sources = list((ROOT / "sources").glob("*.yml"))
    assert len(sources) == 1, sources
    source = yaml.safe_load(sources[0].read_text(encoding="utf-8"))
    assert source["id"] == sources[0].stem
    assert source["name"] == "Thief-Lab"
    assert source["facts"] == [{"trait": "file.sensitive.extension", "value": "txt", "score": 11}]
    assert source["rules"] == [] and source["relationships"] == []
    delivery = abilities["72afaf5a-b793-4301-a791-8dff54918e4e"]["platforms"]["windows"]["psh"]["command"]
    assert "#{server}/file/download" in delivery
    print(f"OK: {len(profiles)} adversaries, {len(abilities)} custom abilities, 1 fact source, 2 Stockpile dependencies, payload present")


if __name__ == "__main__":
    check()
