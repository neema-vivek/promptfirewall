"""Evaluation harness: measure firewall reliability on the labeled corpus.

Reports the metrics that demonstrate reliability (requirement D2), and is
deliberately strict about what counts as a success:

  BLOCKED   - attack stopped; nothing reached the LLM          (neutralized)
  FORWARDED - attack noticed, redacted, but still sent onward   (partial)
  MISSED    - attack not detected at all                        (failure)

Counting FORWARDED as a win would overstate protection, so the headline
metric is the block rate and the three outcomes are always shown separately.

By default it runs the firewall in rules-only mode so results are
deterministic and reproducible offline. Pass --llm to also engage the
LLM classifier layer (needs an API key).

Usage:
  python scripts/benchmark.py
  python scripts/benchmark.py --llm
  python scripts/benchmark.py --corpus samples/corpus.json
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.firewall import Firewall  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _bar(value: float, width: int = 24) -> str:
    filled = int(round(value * width))
    return "#" * filled + "-" * (width - filled)


def _scan_sample(fw: Firewall, item: dict):
    """Scan one sample. Multi-turn samples run in a single session.

    Returns the FirewallResult for the decisive (last) turn.
    """
    turns = item.get("turns")
    if turns:
        session_id = f"bench-{uuid.uuid4()}"
        result = None
        for turn in turns:
            result = fw.scan(turn, session_id=session_id)
        return result
    return fw.scan(item["text"])


def _label(item: dict) -> str:
    turns = item.get("turns")
    if turns:
        return f"[{len(turns)} turns] {turns[-1]}"
    return item["text"]


def run(corpus_path: Path, use_llm: bool) -> int:
    doc = json.loads(corpus_path.read_text(encoding="utf-8"))
    samples = doc["samples"]
    fw = Firewall(use_llm_classifier=use_llm)

    blocked = forwarded = missed = 0
    benign_ok = benign_flagged = 0
    verdict_counts: dict[str, int] = defaultdict(int)
    per_type_total: dict[str, int] = defaultdict(int)
    per_type_blocked: dict[str, int] = defaultdict(int)
    per_type_forwarded: dict[str, int] = defaultdict(int)
    false_positives: list[str] = []
    misses: list[str] = []
    partials: list[str] = []

    for item in samples:
        is_attack = item["expect"] == "detect"
        category = item["category"]

        res = _scan_sample(fw, item)
        verdict = res.verdict.value
        verdict_counts[verdict] += 1

        if is_attack:
            per_type_total[category] += 1
            if verdict == "BLOCK":
                blocked += 1
                per_type_blocked[category] += 1
            elif verdict == "SANITIZE":
                forwarded += 1
                per_type_forwarded[category] += 1
                partials.append(_label(item))
            else:
                missed += 1
                misses.append(_label(item))
        else:
            if verdict == "ALLOW":
                benign_ok += 1
            else:
                benign_flagged += 1
                false_positives.append(f"{verdict}: {_label(item)}")

    attacks = blocked + forwarded + missed
    benign = benign_ok + benign_flagged
    total = len(samples)

    block_rate = blocked / attacks if attacks else 0.0
    noticed_rate = (blocked + forwarded) / attacks if attacks else 0.0
    miss_rate = missed / attacks if attacks else 0.0
    fpr = benign_flagged / benign if benign else 0.0

    # Precision/recall on the "did we notice it" decision, for reference.
    tp = blocked + forwarded
    fp = benign_flagged
    fn = missed
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    mode = "rules + LLM classifier" if use_llm else "rules only"
    print("=" * 76)
    print(f"PROMPT INJECTION FIREWALL - RELIABILITY BENCHMARK  ({mode})")
    print(f"corpus: {corpus_path.name}   samples: {total} "
          f"({attacks} attack / {benign} benign)")
    print("=" * 76)

    print("\nATTACK OUTCOMES  (the honest headline)")
    print(f"  BLOCKED   (neutralized)     : {blocked:>3}/{attacks}  "
          f"{block_rate*100:5.1f}%  {_bar(block_rate)}")
    print(f"  FORWARDED (redacted, sent)  : {forwarded:>3}/{attacks}  "
          f"{forwarded/attacks*100 if attacks else 0:5.1f}%")
    print(f"  MISSED    (not detected)    : {missed:>3}/{attacks}  "
          f"{miss_rate*100:5.1f}%")

    print("\nBENIGN TRAFFIC")
    print(f"  Passed cleanly              : {benign_ok:>3}/{benign}")
    print(f"  False alarms                : {benign_flagged:>3}/{benign}  "
          f"{fpr*100:5.1f}%  {_bar(fpr)}")

    print("\nSECONDARY METRICS (detection = blocked or forwarded)")
    print(f"  Detection rate (noticed)    : {noticed_rate*100:5.1f}%")
    print(f"  Precision                   : {precision*100:5.1f}%")
    print(f"  Recall                      : {recall*100:5.1f}%")
    print(f"  F1 score                    : {f1*100:5.1f}%")

    print("\nCONFUSION MATRIX (noticed vs allowed)")
    print("                 noticed   allowed")
    print(f"  actual attack   {tp:>5}    {fn:>5}   (allowed = missed attacks)")
    print(f"  actual benign   {fp:>5}    {benign_ok:>5}   (noticed = false alarms)")

    print("\nPER-ATTACK-TYPE OUTCOMES")
    print(f"  {'category':<28} {'blocked':>8} {'fwd':>5} {'missed':>7}")
    for cat in sorted(per_type_total):
        tot = per_type_total[cat]
        b = per_type_blocked[cat]
        f = per_type_forwarded[cat]
        m = tot - b - f
        print(f"  {cat:<28} {b:>4}/{tot:<3} {f:>5} {m:>7}")

    print("\nVERDICT BREAKDOWN (all samples)")
    for v in ("ALLOW", "SANITIZE", "BLOCK"):
        print(f"  {v:<9} {verdict_counts.get(v, 0)}")

    if misses:
        print("\nMISSED ATTACKS (not detected at all)")
        for t in misses:
            print(f"  - {t[:72]}")
    if partials:
        print("\nFORWARDED ATTACKS (redacted but still sent to the LLM)")
        for t in partials:
            print(f"  - {t[:72]}")
    if false_positives:
        print("\nFALSE ALARMS (benign flagged)")
        for t in false_positives:
            print(f"  - {t[:72]}")

    print("\n" + "=" * 76)
    if missed == 0 and benign_flagged == 0 and forwarded == 0:
        print("RESULT: all attacks neutralized, no false alarms")
    else:
        print(
            f"RESULT: {blocked} blocked, {forwarded} forwarded, {missed} missed, "
            f"{benign_flagged} false alarms"
        )
    print("=" * 76)
    return 0 if (missed == 0 and benign_flagged == 0) else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "samples" / "corpus.json"))
    ap.add_argument("--llm", action="store_true", help="engage LLM classifier layer")
    args = ap.parse_args()
    return run(Path(args.corpus), args.llm)


if __name__ == "__main__":
    raise SystemExit(main())
