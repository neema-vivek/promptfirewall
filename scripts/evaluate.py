"""Run the firewall against labeled sample sets and print a report.

Usage:
  python scripts/evaluate.py                      # mixed samples.json
  python scripts/evaluate.py instruction_override # focused per-attack report
  python scripts/evaluate.py all                  # every focused *.json set
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running as `python scripts/evaluate.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.firewall import Firewall  # noqa: E402

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


def _run_mixed() -> int:
    fw = Firewall()
    data = json.loads((SAMPLES_DIR / "samples.json").read_text(encoding="utf-8"))

    passed = 0
    print(f"{'VERDICT':<10} {'RISK':<5} {'EXPECTED':<10} RESULT  LABEL")
    print("-" * 78)
    for item in data:
        res = fw.scan(item["text"])
        expected = item["expected_verdict"]
        ok = res.verdict.value == expected
        passed += ok
        print(
            f"{res.verdict.value:<10} {res.risk_score:<5} {expected:<10} "
            f"{'PASS' if ok else 'FAIL':<7} {item['label']}"
        )
        if res.attack_types:
            print(f"           attacks: {', '.join(res.attack_types)}")

    print("-" * 78)
    print(f"{passed}/{len(data)} samples matched expected verdict")
    return 0 if passed == len(data) else 1


def _run_focused(path: Path) -> int:
    fw = Firewall()
    doc = json.loads(path.read_text(encoding="utf-8"))
    attack_type = doc.get("attack_type", path.stem)
    samples = doc["samples"]

    print("=" * 92)
    print(f"COMPLIANCE REPORT: {attack_type}")
    if doc.get("description"):
        print(doc["description"])
    print("=" * 92)
    print(f"{'KIND':<8} {'VERDICT':<10} {'RISK':<5} {'EXPECTED':<10} RESULT  INPUT")
    print("-" * 92)

    passed = 0
    detected = detect_total = 0  # attack detection rate
    allowed = benign_total = 0   # benign pass-through rate

    for item in samples:
        res = fw.scan(item["text"])
        expected = item["expected_verdict"]
        ok = res.verdict.value == expected
        passed += ok
        kind = item.get("kind", "attack")

        if kind == "attack":
            detect_total += 1
            detected += res.verdict.value in ("SANITIZE", "BLOCK")
        else:
            benign_total += 1
            allowed += res.verdict.value == "ALLOW"

        text = item["text"]
        shown = (text[:52] + "...") if len(text) > 55 else text
        print(
            f"{kind:<8} {res.verdict.value:<10} {res.risk_score:<5} "
            f"{expected:<10} {'PASS' if ok else 'FAIL':<7} {shown}"
        )
        if res.attack_types:
            print(f"         -> {', '.join(res.attack_types)}")

    print("-" * 92)
    print(f"Verdict accuracy : {passed}/{len(samples)}")
    if detect_total:
        print(f"Attack detection : {detected}/{detect_total} malicious samples flagged")
    if benign_total:
        print(f"Benign allowed   : {allowed}/{benign_total} legitimate samples passed (false positives: {benign_total - allowed})")
    print()
    return 0 if passed == len(samples) else 1


def main() -> int:
    args = sys.argv[1:]

    if not args:
        return _run_mixed()

    target = args[0]

    if target == "all":
        rc = 0
        for f in sorted(SAMPLES_DIR.glob("*.json")):
            if f.name == "samples.json":
                continue
            rc |= _run_focused(f)
        return rc

    path = SAMPLES_DIR / (target if target.endswith(".json") else f"{target}.json")
    if not path.exists():
        print(f"No sample file: {path}")
        return 2
    return _run_focused(path)


if __name__ == "__main__":
    raise SystemExit(main())
