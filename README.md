# mitre_generator

Turn a list of MITRE ATT&CK technique IDs into an
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer. Each technique is scored
by how often it appears, so the layer becomes a heatmap of, for example, the techniques seen across
a set of incidents, threat reports or detection rules.

![CI](https://github.com/MMoermans/mitre_generator/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

- **Any input**: CSV, a plain list, or IDs pasted from a report (`T1059.001`, `t1566`, …), from files or stdin
- **Sub-techniques roll up**: `T1059.001` also counts for `T1059`, and the parent shows its sub-techniques
- **Current layer format**: Navigator layer format 4.5 for Navigator 5.x (enterprise, mobile or ICS)
- **Optional validation** against the official ATT&CK data: revoked IDs are mapped to their
  replacement, unknown IDs are dropped, and every technique gets its name and a link
- **Gradient scaled to your data**, with a comment on each technique saying how often it was seen
- Standard library only

## Install

```bash
pip install git+https://github.com/MMoermans/mitre_generator.git
```

That gives you the `mitre-generator` command (`python -m mitre` works too). Upgrade with
`pip install -U git+https://github.com/MMoermans/mitre_generator.git`. Without installing, run
`python mitre.py` from a clone: it only needs Python 3.10+.

The ATT&CK data for `--validate` is cached in `~/.cache/mitre_generator` (or `$XDG_CACHE_HOME`).
Delete that folder to free the space (about 1 MB per version) or force a fresh download.

## Usage

```bash
mitre-generator examples/incidents.csv --name "Q3 incidents" --validate
```

```
24 techniques from 22 observations (ATT&CK enterprise v20.1) -> examples/incidents_layer.json
Most frequent: T1059 Command and Scripting Interpreter (5), T1059.001 PowerShell (3), T1486 Data Encrypted for Impact (3), T1566 Phishing (3), T1105 Ingress Tool Transfer (2)
```

Open the [Navigator](https://mitre-attack.github.io/attack-navigator/), choose **Open Existing
Layer → Upload from local**, and select the JSON file.

Running `mitre-generator` without arguments asks for the input and output file names, as the
first version did.

| Option | |
|---|---|
| `inputs` | One or more CSV or text files; `-` reads stdin. Cells without a technique ID (headers, incident numbers) are skipped |
| `-o, --output` | Output file, `-` for stdout. Default: `<input>_layer.json` |
| `--name`, `--description` | Layer name and description |
| `--domain` | `enterprise` (default), `mobile` or `ics` |
| `--validate` | Check IDs against the ATT&CK data from [attack-stix-data](https://github.com/mitre-attack/attack-stix-data). Downloaded once per version and cached in `~/.cache/mitre_generator` |
| `--attack-version` | Pin an ATT&CK version, e.g. `19.1`. Default: the current release |
| `--platforms` | Platform filter, e.g. `"Windows,Linux"`. Default: all platforms |
| `--no-rollup` | Don't add sub-technique counts to the parent technique |
| `--colors LOW HIGH` | Gradient colours. Default: `#92d050` to `#ff0000` |
| `-q, --quiet` | No summary |

More examples:

```bash
# Several reports at once, straight to stdout
mitre-generator report1.txt report2.txt -o - > combined.json

# IDs from another tool
grep -oE 'T[0-9]{4}(\.[0-9]{3})?' rules/*.yml | mitre-generator - -o detections.json --name Detections
```

## Development

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest && ruff check .
```

The tests use a small fake ATT&CK dataset, so they run without network access.

## Changes in 2.0

- The layer declared ATT&CK version 13 under a misspelled key (`" attack"`), and format 4.4 with
  Navigator 4.8.2. It now writes format 4.5 with no ATT&CK version (the Navigator then uses the
  current one) or the version it validated against
- The gradient was fixed at 0-4, so anything seen more than four times had the same colour. It
  now runs up to the highest score
- The platform filter listed outdated names such as "Azure AD" and "PRE", which hid techniques. It
  is now left out unless you ask for one
- Installable with pip as `mitre-generator`; command-line options, multiple inputs, stdin, validation, revoked-ID mapping, tests and CI
