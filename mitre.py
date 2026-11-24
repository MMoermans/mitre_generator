"""Turn a list of MITRE ATT&CK technique IDs into an ATT&CK Navigator layer.

Each technique is scored by how often it appears in the input, so the layer becomes a heatmap
(for example of the techniques seen across a set of incidents or threat reports). Optionally the
IDs are checked against the official ATT&CK data: unknown IDs are dropped, revoked IDs are mapped
to their replacement and technique names are added.

Run without arguments for the interactive prompts, or see ``python mitre.py --help``.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import time
import urllib.request
from collections import Counter
from datetime import date
from pathlib import Path

__version__ = "2.0.0"

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.3.2"
DOMAINS = ("enterprise", "mobile", "ics")
DEFAULT_COLORS = ("#92d050", "#ff0000")  # low -> high, as in earlier versions

STIX_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
INDEX_MAX_AGE = 24 * 3600
USER_AGENT = f"mitre_generator/{__version__}"

# Not inside a longer token: "T1059.0012", "XT1000" and "T1003.001x" are not IDs, but "...used T1566." is.
TECHNIQUE_RE = re.compile(r"(?<![A-Za-z0-9])T(\d{4})(?:\.(\d{3}))?(?![A-Za-z0-9]|\.\d)", re.IGNORECASE)


# ------------------------------------------------------------------------------------------------
# Reading technique IDs
# ------------------------------------------------------------------------------------------------
def extract_ids(text: str) -> list[str]:
    """All technique IDs in a piece of text, normalised to upper case, in order of appearance."""
    return [f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "") for m in TECHNIQUE_RE.finditer(text)]


def read_input(text: str) -> tuple[list[str], list[str]]:
    """Technique IDs from CSV or free text, plus the non-empty cells that held no ID (e.g. headers)."""
    ids: list[str] = []
    skipped: list[str] = []
    for row in csv.reader(io.StringIO(text)):
        for cell in row:
            cell = cell.strip()
            if not cell:
                continue
            found = extract_ids(cell)
            if found:
                ids.extend(found)
            else:
                skipped.append(cell)
    return ids, skipped


def parent_of(technique_id: str) -> str:
    return technique_id.split(".")[0]


def count_techniques(ids: list[str], rollup: bool = True) -> tuple[Counter, Counter]:
    """Occurrences per technique. With rollup, each sub-technique also counts for its parent.

    Returns the scores and, per parent, how much of its score came from sub-techniques.
    """
    scores: Counter = Counter()
    via_subs: Counter = Counter()
    for tid in ids:
        scores[tid] += 1
        if rollup and "." in tid:
            scores[parent_of(tid)] += 1
            via_subs[parent_of(tid)] += 1
    return scores, via_subs


# ------------------------------------------------------------------------------------------------
# ATT&CK data (optional validation)
# ------------------------------------------------------------------------------------------------
def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(Path.home(), ".cache")
    return Path(base) / "mitre_generator"


def _download(url: str, timeout: float = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URLs
        return resp.read()


def _write_atomic(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    tmp.replace(path)


def stix_index(fetch=None) -> dict:
    """MITRE's index of ATT&CK releases, cached for a day."""
    fetch = fetch or _download
    path = cache_dir() / "index.json"
    try:
        if time.time() - path.stat().st_mtime < INDEX_MAX_AGE:
            return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    try:
        data = json.loads(fetch(STIX_INDEX_URL))
    except Exception:
        if path.exists():  # a stale index beats none
            return json.loads(path.read_text(encoding="utf-8"))
        raise
    _write_atomic(path, json.dumps(data))
    return data


def release_url(index: dict, domain: str, version: str | None) -> tuple[str, str]:
    """Download URL and version of the requested (or latest) release for a domain."""
    name = f"{domain}-attack"
    for collection in index.get("collections", []):
        versions = collection.get("versions") or []
        if not versions or f"/{name}/" not in versions[0].get("url", ""):
            continue
        if version is None:
            return versions[0]["url"], versions[0]["version"]
        for v in versions:
            if v["version"] == version or v["version"] == f"{version}.0":
                return v["url"], v["version"]
        available = ", ".join(v["version"] for v in versions[:8])
        raise ValueError(f"ATT&CK {domain} version {version} not found (recent versions: {available})")
    raise ValueError(f"no ATT&CK data for domain '{domain}'")


def summarise_bundle(bundle: dict) -> dict:
    """Reduce a 50 MB STIX bundle to what the layer needs: names, status and revocations."""
    techniques: dict[str, dict] = {}
    by_stix: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        refs = obj.get("external_references", [])
        ext = next((r for r in refs if r.get("source_name", "").startswith("mitre")), None)
        if not ext or not ext.get("external_id"):
            continue
        tid = ext["external_id"].upper()
        by_stix[obj["id"]] = tid
        techniques[tid] = {
            "name": obj.get("name", ""),
            "revoked": bool(obj.get("revoked")),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
            "url": ext.get("url", ""),
        }
    for obj in bundle.get("objects", []):
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            old = by_stix.get(obj.get("source_ref"))
            new = by_stix.get(obj.get("target_ref"))
            if old and new and old in techniques:
                techniques[old]["revoked_by"] = new
    return techniques


def load_attack(domain: str, version: str | None = None, fetch=None) -> tuple[dict, str]:
    """Technique catalogue for a domain and the ATT&CK version it came from (cached per version)."""
    fetch = fetch or _download
    url, resolved = release_url(stix_index(fetch), domain, version)
    path = cache_dir() / f"{domain}-attack-{resolved}.summary.json"
    try:
        return json.loads(path.read_text(encoding="utf-8")), resolved
    except (OSError, ValueError):
        pass
    print(f"Downloading ATT&CK {domain} v{resolved} (once; it is cached afterwards)...", file=sys.stderr)
    catalogue = summarise_bundle(json.loads(fetch(url)))
    _write_atomic(path, json.dumps(catalogue))
    return catalogue, resolved


def resolve_ids(ids: list[str], catalogue: dict) -> tuple[list[str], list[str]]:
    """Map revoked IDs to their replacement and drop unknown ones. Returns (ids, messages)."""
    out: list[str] = []
    notes: list[str] = []
    unknown: Counter = Counter()
    replaced: dict[str, str] = {}
    deprecated: set[str] = set()
    for original in ids:
        tid = original
        seen = {tid}
        while tid in catalogue and catalogue[tid].get("revoked_by"):  # follow revocation chains
            tid = catalogue[tid]["revoked_by"]
            if tid in seen:  # a cycle would be a data error; stop rather than loop
                break
            seen.add(tid)
        if tid != original:
            replaced[original] = tid
        if tid not in catalogue:
            unknown[tid] += 1
            continue
        if catalogue[tid].get("deprecated"):
            deprecated.add(tid)
        out.append(tid)
    for old, new in sorted(replaced.items()):
        notes.append(f"{old} was revoked; counted as {new} ({catalogue.get(new, {}).get('name', '')})")
    for tid in sorted(deprecated):
        notes.append(f"{tid} ({catalogue[tid]['name']}) is deprecated and may not appear in the Navigator")
    for tid, n in sorted(unknown.items()):
        notes.append(f"{tid} is not an ATT&CK technique in this version; skipped ({n}x)")
    return out, notes


# ------------------------------------------------------------------------------------------------
# Building the layer
# ------------------------------------------------------------------------------------------------
def build_layer(
    scores: Counter,
    via_subs: Counter | None = None,
    *,
    name: str = "Technique heatmap",
    description: str = "",
    domain: str = "enterprise",
    attack_version: str | None = None,
    platforms: list[str] | None = None,
    colors: tuple[str, str] = DEFAULT_COLORS,
    catalogue: dict | None = None,
    sources: list[str] | None = None,
) -> dict:
    """An ATT&CK Navigator layer (format 4.5) with one scored technique per ID."""
    via_subs = via_subs or Counter()
    catalogue = catalogue or {}
    parents_with_subs = {parent_of(t) for t in scores if "." in t}
    techniques = []
    for tid, score in sorted(scores.items(), key=lambda kv: (-kv[1], kv[0])):
        comment = f"Seen {score}×"
        if via_subs.get(tid):
            comment += f" ({via_subs[tid]} via sub-techniques)"
        entry = {
            "techniqueID": tid,
            "score": score,
            "color": "",
            "comment": comment,
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": tid in parents_with_subs,
        }
        info = catalogue.get(tid)
        if info and info.get("url"):
            entry["links"] = [{"label": info.get("name") or tid, "url": info["url"]}]
        techniques.append(entry)

    versions = {"navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION}
    if attack_version:
        versions["attack"] = str(attack_version)

    layer = {
        "name": name,
        "versions": versions,
        "domain": f"{domain}-attack",
        "description": description,
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": list(colors),
            "minValue": 0,
            "maxValue": max(scores.values(), default=1) or 1,
        },
        "legendItems": [],
        "metadata": [{"name": "generated", "value": date.today().isoformat()}]
        + ([{"name": "source", "value": ", ".join(sources)}] if sources else []),
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
    if platforms:
        layer["filters"] = {"platforms": platforms}
    return layer


# ------------------------------------------------------------------------------------------------
# Command line
# ------------------------------------------------------------------------------------------------
HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mitre.py",
        description="Create an ATT&CK Navigator layer (heatmap) from technique IDs in CSV or text files.",
        epilog="Example: python mitre.py incidents.csv -o layer.json --name 'Q3 incidents' --validate",
    )
    p.add_argument("inputs", nargs="*", help="CSV or text files with technique IDs ('-' for stdin)")
    p.add_argument("-o", "--output", help="output JSON file ('-' for stdout; default: <first input>_layer.json)")
    p.add_argument("--name", help="layer name (default: the input file name)")
    p.add_argument("--description", help="layer description")
    p.add_argument("--domain", choices=DOMAINS, default="enterprise", help="ATT&CK domain (default: enterprise)")
    p.add_argument("--attack-version", help="ATT&CK version for the layer, e.g. 20 (default: current)")
    p.add_argument("--platforms", help="comma-separated platform filter, e.g. 'Windows,Linux' (default: all)")
    p.add_argument("--no-rollup", action="store_true", help="do not add sub-technique counts to their parent")
    p.add_argument("--colors", nargs=2, metavar=("LOW", "HIGH"), help="gradient colours, e.g. '#ffffff' '#ff0000'")
    p.add_argument("--validate", action="store_true",
                   help="check IDs against the official ATT&CK data (downloads it once, then cached)")
    p.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def interactive_args() -> argparse.Namespace:
    """The original prompt-driven flow, for running the script without arguments."""
    inp = input("Input CSV filename with T-numbers: ").strip()
    out = input("Output JSON filename for ATT&CK Navigator layer: ").strip()
    if not inp:
        raise SystemExit("No input file name provided.")
    return parse_args([inp] + (["-o", out] if out else []))


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = interactive_args() if not argv and sys.stdin.isatty() else parse_args(argv)
    if not args.inputs:
        args.inputs = ["-"]

    colors = tuple(args.colors) if args.colors else DEFAULT_COLORS
    if not all(HEX_COLOR.match(c) for c in colors):
        print("error: colours must be hex values like #ff0000", file=sys.stderr)
        return 2

    ids: list[str] = []
    skipped: list[str] = []
    for src in args.inputs:
        try:
            text = sys.stdin.read() if src == "-" else Path(src).read_text(encoding="utf-8-sig")
        except OSError as exc:
            print(f"error: cannot read {src}: {exc.strerror or exc}", file=sys.stderr)
            return 2
        found, rest = read_input(text)
        ids.extend(found)
        skipped.extend(rest)

    notes: list[str] = []
    catalogue: dict = {}
    attack_version = args.attack_version
    if args.validate:
        try:
            catalogue, attack_version = load_attack(args.domain, args.attack_version)
        except Exception as exc:  # network, missing version, bad data
            print(f"error: could not load ATT&CK data: {exc}", file=sys.stderr)
            return 1
        ids, notes = resolve_ids(ids, catalogue)

    if not ids:
        print("error: no technique IDs (like T1059 or T1059.001) found in the input", file=sys.stderr)
        return 1

    scores, via_subs = count_techniques(ids, rollup=not args.no_rollup)
    files = [s for s in args.inputs if s != "-"]
    name = args.name or (Path(files[0]).stem if files else "Technique heatmap")
    description = args.description or (
        f"{len(ids)} technique observations from {', '.join(Path(f).name for f in files) or 'stdin'}"
    )
    platforms = [x.strip() for x in args.platforms.split(",") if x.strip()] if args.platforms else None
    layer = build_layer(scores, via_subs, name=name, description=description, domain=args.domain,
                        attack_version=attack_version, platforms=platforms, colors=colors,
                        catalogue=catalogue, sources=[Path(f).name for f in files])

    output = args.output or (f"{Path(files[0]).with_suffix('')}_layer.json" if files else "-")
    text = json.dumps(layer, indent=2, ensure_ascii=False) + "\n"
    if output == "-":
        sys.stdout.write(text)
    else:
        Path(output).write_text(text, encoding="utf-8")

    if not args.quiet:
        err = sys.stderr
        print(f"{len(scores)} techniques from {len(ids)} observations"
              f"{f' (ATT&CK {args.domain} v{attack_version})' if attack_version else ''}"
              f"{'' if output == '-' else f' -> {output}'}", file=err)
        top = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        print("Most frequent: " + ", ".join(
            f"{t}{' ' + catalogue[t]['name'] if t in catalogue else ''} ({n})" for t, n in top), file=err)
        if skipped:
            sample = ", ".join(repr(s[:30]) for s in skipped[:5])
            print(f"Skipped {len(skipped)} cell(s) without a technique ID: {sample}"
                  f"{' ...' if len(skipped) > 5 else ''}", file=err)
        for note in notes:
            print(f"note: {note}", file=err)
    return 0


if __name__ == "__main__":
    sys.exit(main())
