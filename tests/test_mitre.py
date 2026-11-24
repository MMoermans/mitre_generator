import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mitre  # noqa: E402

# A tiny ATT&CK-like STIX bundle: T1086 (old PowerShell) was revoked by T1059.001.
BUNDLE = {
    "type": "bundle",
    "objects": [
        {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Command and Scripting Interpreter",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1059",
                                  "url": "https://attack.mitre.org/techniques/T1059"}]},
        {"type": "attack-pattern", "id": "attack-pattern--2", "name": "PowerShell",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001",
                                  "url": "https://attack.mitre.org/techniques/T1059/001"}]},
        {"type": "attack-pattern", "id": "attack-pattern--3", "name": "PowerShell", "revoked": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1086"}]},
        {"type": "attack-pattern", "id": "attack-pattern--4", "name": "Old Thing", "x_mitre_deprecated": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1099"}]},
        {"type": "attack-pattern", "id": "attack-pattern--5", "name": "Phishing",
         "external_references": [{"source_name": "capec", "external_id": "CAPEC-98"},
                                 {"source_name": "mitre-attack", "external_id": "T1566"}]},
        {"type": "relationship", "relationship_type": "revoked-by",
         "source_ref": "attack-pattern--3", "target_ref": "attack-pattern--2"},
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Ignored"},
    ],
}
INDEX = {"collections": [
    {"versions": [
        {"version": "20.1", "url": "https://example.test/enterprise-attack/enterprise-attack-20.1.json"},
        {"version": "20.0", "url": "https://example.test/enterprise-attack/enterprise-attack-20.0.json"},
    ]},
    {"versions": [{"version": "20.1", "url": "https://example.test/mobile-attack/mobile-attack-20.1.json"}]},
]}


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.chdir(tmp_path)


def fake_fetch(calls):
    def fetch(url, timeout=120):
        calls.append(url)
        if url == mitre.STIX_INDEX_URL:
            return json.dumps(INDEX).encode()
        if url.endswith("enterprise-attack-20.1.json") or url.endswith("enterprise-attack-20.0.json"):
            return json.dumps(BUNDLE).encode()
        raise OSError(f"unexpected URL {url}")
    return fetch


# --- reading input --------------------------------------------------------------------------------
def test_extract_ids_from_messy_text():
    text = "Seen: t1059.001 (PowerShell), T1566; also T1003.001x? not T12345 nor XT1000 nor T1059.0012"
    assert mitre.extract_ids(text) == ["T1059.001", "T1566"]
    assert mitre.extract_ids("The actor used T1566. Then T1059.") == ["T1566", "T1059"]


def test_read_input_skips_headers_and_empty_cells():
    ids, skipped = mitre.read_input("technique,notes\nT1059.001,,\n , T1566 - Phishing\n\nT0800\n")
    assert ids == ["T1059.001", "T1566", "T0800"]
    assert skipped == ["technique", "notes"]


def test_count_rolls_sub_techniques_up_to_the_parent():
    scores, via = mitre.count_techniques(["T1059.001", "T1059.003", "T1059", "T1566"])
    assert scores == {"T1059.001": 1, "T1059.003": 1, "T1059": 3, "T1566": 1}
    assert via == {"T1059": 2}
    scores, via = mitre.count_techniques(["T1059.001"], rollup=False)
    assert scores == {"T1059.001": 1} and not via


# --- the layer ------------------------------------------------------------------------------------
def test_layer_matches_navigator_format_4_5():
    scores, via = mitre.count_techniques(["T1059.001", "T1059.001", "T1566"])
    layer = mitre.build_layer(scores, via, name="Test", attack_version="20.1", platforms=["Windows"])
    assert layer["versions"] == {"navigator": mitre.NAVIGATOR_VERSION, "layer": "4.5", "attack": "20.1"}
    assert " attack" not in layer["versions"]  # the bug in version 1
    assert layer["domain"] == "enterprise-attack"
    assert layer["gradient"]["maxValue"] == 2  # scaled to the data, not a fixed 4
    assert layer["filters"] == {"platforms": ["Windows"]}
    t = {x["techniqueID"]: x for x in layer["techniques"]}
    assert t["T1059"]["showSubtechniques"] is True
    assert t["T1059"]["comment"] == "Seen 2× (2 via sub-techniques)"
    assert [x["techniqueID"] for x in layer["techniques"]] == ["T1059", "T1059.001", "T1566"]


def test_layer_omits_optional_fields_it_cannot_know():
    layer = mitre.build_layer(mitre.Counter({"T1566": 1}))
    assert "attack" not in layer["versions"]  # Navigator then uses the current ATT&CK version
    assert "filters" not in layer  # all platforms
    assert layer["gradient"]["maxValue"] == 1


# --- ATT&CK data ----------------------------------------------------------------------------------
def test_summarise_bundle_and_revocations():
    cat = mitre.summarise_bundle(BUNDLE)
    assert set(cat) == {"T1059", "T1059.001", "T1086", "T1099", "T1566"}
    assert cat["T1086"]["revoked_by"] == "T1059.001"
    assert cat["T1099"]["deprecated"] is True
    assert cat["T1566"]["name"] == "Phishing"  # mitre-attack reference found after a CAPEC one


def test_resolve_ids_maps_revoked_and_drops_unknown():
    cat = mitre.summarise_bundle(BUNDLE)
    ids, notes = mitre.resolve_ids(["T1086", "T9999", "T1099", "T1566", "T9999"], cat)
    assert ids == ["T1059.001", "T1099", "T1566"]
    assert any("T1086 was revoked; counted as T1059.001" in n for n in notes)
    assert any("T1099" in n and "deprecated" in n for n in notes)
    assert any("T9999" in n and "(2x)" in n for n in notes)


def test_load_attack_downloads_once_then_uses_the_cache():
    calls = []
    cat, version = mitre.load_attack("enterprise", fetch=fake_fetch(calls))
    assert version == "20.1" and "T1566" in cat
    cat2, _ = mitre.load_attack("enterprise", fetch=fake_fetch(calls))
    assert cat2 == cat
    assert len([c for c in calls if c.endswith(".json") and "enterprise-attack-" in c]) == 1


def test_release_url_selects_versions_and_explains_missing_ones():
    assert mitre.release_url(INDEX, "enterprise", "20")[1] == "20.0"
    assert mitre.release_url(INDEX, "mobile", None)[1] == "20.1"
    with pytest.raises(ValueError, match="recent versions: 20.1, 20.0"):
        mitre.release_url(INDEX, "enterprise", "7")
    with pytest.raises(ValueError, match="no ATT&CK data"):
        mitre.release_url(INDEX, "ics", None)


# --- command line ---------------------------------------------------------------------------------
def test_cli_writes_a_layer_next_to_the_input(tmp_path, capsys):
    (tmp_path / "incidents.csv").write_text("technique\nT1059.001\nT1059.001,T1566\n", encoding="utf-8")
    assert mitre.main(["incidents.csv"]) == 0
    layer = json.loads((tmp_path / "incidents_layer.json").read_text(encoding="utf-8"))
    assert layer["name"] == "incidents"
    assert {t["techniqueID"]: t["score"] for t in layer["techniques"]} == {"T1059": 2, "T1059.001": 2, "T1566": 1}
    err = capsys.readouterr().err
    assert "3 techniques from 3 observations" in err
    assert "Skipped 1 cell(s)" in err


def test_cli_validate_uses_attack_data(tmp_path, capsys, monkeypatch):
    calls = []
    monkeypatch.setattr(mitre, "_download", fake_fetch(calls))
    (tmp_path / "old.csv").write_text("T1086\nT9999\n", encoding="utf-8")
    assert mitre.main(["old.csv", "-o", "-", "--validate", "--name", "Old"]) == 0
    out = capsys.readouterr()
    layer = json.loads(out.out)
    assert layer["versions"]["attack"] == "20.1"
    assert {t["techniqueID"] for t in layer["techniques"]} == {"T1059", "T1059.001"}
    assert layer["techniques"][0]["links"][0]["url"].startswith("https://attack.mitre.org/")
    assert "T1086 was revoked" in out.err and "T9999" in out.err


def test_cli_errors(tmp_path, capsys):
    assert mitre.main(["missing.csv"]) == 2
    (tmp_path / "empty.csv").write_text("nothing here\n", encoding="utf-8")
    assert mitre.main(["empty.csv"]) == 1
    assert mitre.main(["empty.csv", "--colors", "red", "#ff0000"]) == 2
    assert "no technique IDs" in capsys.readouterr().err


def test_cli_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO("T1566.001 T1566.002"))
    assert mitre.main(["-", "-o", "-", "-q", "--no-rollup"]) == 0
    layer = json.loads(capsys.readouterr().out)
    assert {t["techniqueID"] for t in layer["techniques"]} == {"T1566.001", "T1566.002"}
