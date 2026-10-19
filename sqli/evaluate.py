"""Evaluate grammar scanner vs keyword blacklist on the labelled datasets."""
import os

from .detector import scan
from .blacklist import blacklist_scan

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def load_queries(filename):
    path = filename if os.path.isabs(filename) else os.path.join(DATA_DIR, filename)
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]


def evaluate(policy=None):
    """Return a list of rows: (query, is_injection_truth, grammar_flagged, blacklist_flagged)."""
    rows = []
    for q in load_queries("normal_queries.txt"):
        rows.append((q, False, scan(q, policy).injection, blacklist_scan(q)[0]))
    for q in load_queries("injected_queries.txt"):
        rows.append((q, True, scan(q, policy).injection, blacklist_scan(q)[0]))
    return rows


def summarize(rows):
    inj = [r for r in rows if r[1]]
    nor = [r for r in rows if not r[1]]
    return {
        "injected": len(inj),
        "normal": len(nor),
        "grammar_detected": sum(r[2] for r in inj),
        "blacklist_detected": sum(r[3] for r in inj),
        "grammar_false_positives": sum(r[2] for r in nor),
        "blacklist_false_positives": sum(r[3] for r in nor),
    }


def format_table(rows):
    def mark(flagged, truth):
        if truth:
            return "BLOCKED" if flagged else "MISSED "
        return "FALSE+  " if flagged else "ok      "
    lines = [f"{'#':>2}  {'Truth':<9} {'Grammar':<9} {'Blacklist':<9} Query", "-" * 100]
    for i, (q, truth, g, b) in enumerate(rows, 1):
        lines.append(f"{i:>2}  {'INJECTED' if truth else 'normal':<9} {mark(g, truth):<9} {mark(b, truth):<9} {q}")
    s = summarize(rows)
    lines += [
        "-" * 100,
        f"Grammar scanner : detected {s['grammar_detected']}/{s['injected']} injections, "
        f"{s['grammar_false_positives']}/{s['normal']} false positives",
        f"Keyword blacklist: detected {s['blacklist_detected']}/{s['injected']} injections, "
        f"{s['blacklist_false_positives']}/{s['normal']} false positives",
    ]
    return "\n".join(lines)
