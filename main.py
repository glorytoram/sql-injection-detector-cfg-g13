#!/usr/bin/env python3
"""
SQL Injection Detector via Grammar Analysis
Theory of Computation (BIS503) - Mini Project 13

Usage examples
  python main.py --sample                 # the 3 queries from the project brief
  python main.py -q "SELECT * FROM users WHERE id = '' OR '1'='1'" --tree
  python main.py --file data/injected_queries.txt
  python main.py --evaluate               # 10 normal + 10 injected: grammar vs blacklist
  python main.py --bypass                 # injections that beat the blacklist
  python main.py --sqlite-demo            # real effect on an in-memory sqlite3 database
  python main.py --interactive            # type queries one by one
  python main.py --sample --strict        # also flag ANY AND/OR branch in WHERE
  python main.py -q "..." --dot out/      # export parse tree (DOT + Mermaid) for diagrams
"""
import argparse
import os
import sys

from sqli import scan, Policy, blacklist_scan
from sqli.evaluate import load_queries, evaluate, format_table
from sqli.report import format_result
from sqli.sqlite_demo import run_demo
from sqli.tree import to_dot, to_mermaid

SAMPLE_QUERIES = [
    "SELECT * FROM users WHERE id = '5'",
    "SELECT * FROM users WHERE id = '' OR '1'='1'",
    "SELECT * FROM users WHERE id = '' OR 1=1--",
]


def export_tree(res, outdir, stem):
    if res.tree is None:
        print(f"  (no parse tree to export for {stem}: query did not parse)")
        return
    os.makedirs(outdir, exist_ok=True)
    for ext, text in (("dot", to_dot(res.tree)), ("mmd", to_mermaid(res.tree))):
        path = os.path.join(outdir, f"{stem}.{ext}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"  wrote {path}")


def scan_many(queries, policy, args, prefix="Query"):
    flagged = 0
    for i, q in enumerate(queries, 1):
        res = scan(q, policy)
        flagged += res.injection
        print(format_result(res, f"{prefix} {i}", show_tree=args.tree))
        if args.compare:
            blocked, matched = blacklist_scan(q)
            print(f"  Keyword blacklist: {'BLOCKED ' + str(matched) if blocked else 'PASSED (not detected)'}")
        if args.dot:
            export_tree(res, args.dot, f"query_{i}")
        print()
    print(f"Summary: {flagged} of {len(queries)} queries flagged as injection.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Grammar-based SQL injection scanner (CFG + parse tree analysis).")
    ap.add_argument("-q", "--query", action="append", help="query to scan (repeatable)")
    ap.add_argument("-f", "--file", help="text file with one query per line")
    ap.add_argument("--sample", action="store_true", help="run the 3 sample queries from the project brief")
    ap.add_argument("--evaluate", action="store_true", help="grammar scanner vs blacklist on the datasets")
    ap.add_argument("--bypass", action="store_true", help="show injections that bypass the blacklist")
    ap.add_argument("--sqlite-demo", action="store_true", help="execute queries against an in-memory sqlite3 DB")
    ap.add_argument("--interactive", action="store_true", help="read queries from the keyboard")
    ap.add_argument("--strict", action="store_true", help="flag ANY AND/OR branch in WHERE")
    ap.add_argument("--tree", action="store_true", help="print the full parse tree")
    ap.add_argument("--compare", action="store_true", help="also show the keyword-blacklist verdict")
    ap.add_argument("--dot", metavar="DIR", help="export parse trees as Graphviz .dot and Mermaid .mmd")
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    policy = Policy(allow_and=not args.strict)
    did_something = False

    if args.sample:
        did_something = True
        print("=== Sample queries from the project brief ===\n")
        scan_many(SAMPLE_QUERIES, policy, args)
    if args.query:
        did_something = True
        scan_many(args.query, policy, args)
    if args.file:
        did_something = True
        scan_many(load_queries(args.file), policy, args)
    if args.evaluate:
        did_something = True
        print("=== Evaluation: 10 normal + 10 injected queries ===\n")
        print(format_table(evaluate(policy)))
    if args.bypass:
        did_something = True
        print("=== Injections that BYPASS the keyword blacklist ===\n")
        args.compare = True
        scan_many(load_queries("bypass_queries.txt"), policy, args, prefix="Attack")
    if args.sqlite_demo:
        did_something = True
        run_demo()
    if args.interactive:
        did_something = True
        print("Type a SQL query (empty line to quit).")
        while True:
            try:
                q = input("sql> ").strip()
            except EOFError:
                break
            if not q:
                break
            print(format_result(scan(q, policy), "Result", show_tree=args.tree))
            print()
    if not did_something:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
