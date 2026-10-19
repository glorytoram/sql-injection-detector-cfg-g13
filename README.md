# SQL Injection Detector via Grammar Analysis

**Theory of Computation (BIS503) · Section B · 5th Semester, Information Science & Engineering**
**Mini Project 13 · Group 13**

| | |
|---|---|
| **Theory concept** | Context-Free Grammar (CFG): ambiguity and parse-tree analysis |
| **Application area** | Cybersecurity: Web Application Firewall (WAF) logic |
| **Language** | Python 3.8+ (standard library only, no third-party packages) |
| **Team size** | 4 students |

---

## Table of Contents

1. [Overview](#1-overview)
2. [Theory Background](#2-theory-background)
3. [Features](#3-features)
4. [Project Structure](#4-project-structure)
5. [Requirements and Installation](#5-requirements-and-installation)
6. [How to Run](#6-how-to-run)
7. [Expected Output](#7-expected-output)
8. [Test Cases](#8-test-cases)
9. [The Grammar](#9-the-grammar)
10. [Detection Rules](#10-detection-rules)
11. [Evaluation: Grammar vs Blacklist](#11-evaluation-grammar-vs-blacklist)
12. [Policy and Configuration](#12-policy-and-configuration)
13. [Mapping to the Project Brief](#13-mapping-to-the-project-brief)
14. [Team and Contributions](#14-team-and-contributions)
15. [Limitations](#15-limitations)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. Overview

SQL injection works by changing the **grammatical structure** of a query. A normal query such as

```sql
SELECT * FROM users WHERE id = '5'
```

has one parse tree, with a single equality condition under `WHERE`. An injected query such as

```sql
SELECT * FROM users WHERE id = '' OR '1'='1'
```

has a structurally different parse tree. The `WHERE` clause now contains an `OR` branch that the developer never intended.

This project builds a scanner that:

1. **Tokenizes** the query with a DFA-style lexer.
2. **Parses** it with a recursive-descent parser for a Context-Free Grammar of basic SQL `SELECT`.
3. **Inspects the parse tree** for structure the application never intended: extra `OR` branches, tautologies, `UNION` grafts, stacked queries, comments.
4. **Explains** why each query was flagged.
5. **Compares** itself against a naive keyword blacklist and shows injections that slip past the blacklist but are caught by the grammar.

This is stronger than keyword blacklisting, which misses obfuscated injections and can also block harmless input.

> The real fix for SQL injection is parameterized queries (prepared statements). This project shows *why* grammar analysis beats plain string matching, and how a WAF can reason about query structure.

---

## 2. Theory Background

| Concept | Where it appears in this project |
|---|---|
| **DFA** | The lexer (`sqli/lexer.py`) reads the query one character at a time and groups characters into tokens. |
| **Context-Free Grammar** | The SQL grammar in `docs/grammar.md`, implemented by the parser in `sqli/parser.py`. |
| **Derivation and parse tree** | Every accepted query produces a parse tree (`sqli/tree.py`). |
| **Ambiguity** | The naive rule `condition → condition OR condition \| condition AND condition` is ambiguous. Our layered grammar (`condition → and_expr → not_expr → primary`) gives every query exactly one tree. |
| **Operator precedence via grammar structure** | `NOT` binds tighter than `AND`, which binds tighter than `OR`, encoded directly in the rule layering. |

---

## 3. Features

- DFA-style lexer for 12 token types, including comments (`--`, `#`, `/* */`) and escaped quotes (`''`)
- Recursive-descent parser for single-table `SELECT` with `WHERE`, `ORDER BY`, `LIMIT`, `UNION`, `LIKE`, `IN`, `NOT`, parentheses
- 9 structural detection rules (see [section 10](#10-detection-rules))
- A human-readable explanation for every flagged query
- Parse-tree output as ASCII, Graphviz DOT and Mermaid
- Keyword blacklist baseline for comparison
- Evaluation harness: 10 normal + 10 injected queries, grammar vs blacklist
- Bypass demonstration: injections that beat the blacklist
- `sqlite3` demo showing the real effect of each attack, with and without the scanner
- Interactive mode, file mode and a strict policy mode
- 21 unit tests

---

## 4. Project Structure

```
sql-injection-detector-cfg-g13/
├── main.py                  CLI entry point
├── generate_docs.py         Regenerates docs/parse_trees.md and docs/evaluation_results.md
├── requirements.txt         Dependencies (none required)
├── README.md                This file
├── LICENSE                  MIT licence
│
├── sqli/                    Core package
│   ├── __init__.py
│   ├── lexer.py             DFA-style tokenizer
│   ├── parser.py            Recursive-descent parser for the SQL CFG -> parse tree
│   ├── tree.py              Parse-tree node + ASCII / Graphviz DOT / Mermaid export
│   ├── detector.py          Structural anomaly detector (the scanner) and Policy
│   ├── blacklist.py         Naive keyword blacklist (for comparison)
│   ├── evaluate.py          Grammar vs blacklist evaluation
│   ├── sqlite_demo.py       sqlite3 demo of the real effect of each query
│   └── report.py            Console formatting
│
├── data/                    Test datasets
│   ├── normal_queries.txt   10 legitimate queries
│   ├── injected_queries.txt 10 injected queries
│   └── bypass_queries.txt   Injections that bypass the blacklist
│
├── tests/
│   └── test_scanner.py      21 unit tests (lexer, parser, detector, datasets)
│
└── docs/
    ├── grammar.md           The CFG, ambiguity discussion, detection rules, limitations
    ├── parse_trees.md       Normal vs injected parse trees (generated)
    ├── evaluation_results.md  Comparison tables (generated)
    └── slides_outline.md    10-slide presentation outline
```

### How the pipeline fits together

```
 SQL query text
      │
      ▼
 ┌───────────┐    ┌───────────┐    ┌──────────────────┐    ┌──────────────┐
 │  Lexer    │ →  │  Parser   │ →  │ Structural       │ →  │  Verdict +   │
 │ (tokens)  │    │ (CFG →    │    │ analyser         │    │  explanation │
 │           │    │ parse tree)│   │ (walk the tree)  │    │              │
 └───────────┘    └───────────┘    └──────────────────┘    └──────────────┘
   lexer.py         parser.py         detector.py              report.py
                    tree.py
```

---

## 5. Requirements and Installation

### Requirements

- **Python 3.8 or newer**
- No third-party packages. The project uses only the standard library (`re`, `sqlite3`, `argparse`, `unittest`, `dataclasses`).
- *Optional:* [Graphviz](https://graphviz.org) if you want to render exported `.dot` files as images.

### Check your Python version

```bash
python --version
```

On some systems the command is `python3` instead of `python`. Use whichever works on your machine.

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/glorytoram/sql-injection-detector-cfg-g13.git

# 2. Enter the project folder
cd sql-injection-detector-cfg-g13

# 3. (Optional) install requirements; this installs nothing extra
pip install -r requirements.txt
```

There is **no build step**. The project runs directly from source.

---

## 6. How to Run

All commands are run from the project root folder.

### Command reference

| Command | What it does |
|---|---|
| `python main.py --sample` | Scans the 3 sample queries from the project brief |
| `python main.py --sample --tree` | Same, and prints the full parse tree of each query |
| `python main.py --evaluate` | Table of 10 normal + 10 injected queries: grammar scanner vs blacklist |
| `python main.py --bypass` | Shows injections that beat the blacklist but are caught by the grammar |
| `python main.py --sqlite-demo` | Runs queries on an in-memory sqlite3 DB, with and without the scanner |
| `python main.py -q "<query>"` | Scans one query you type on the command line |
| `python main.py -q "<query>" --tree --compare` | Scans one query, prints the tree and the blacklist verdict |
| `python main.py --file data/injected_queries.txt` | Scans every query in a text file (one per line) |
| `python main.py --interactive` | Type queries one at a time; press Enter on an empty line to quit |
| `python main.py --sample --strict` | Strict policy: also flags any `AND` branch in `WHERE` |
| `python main.py --sample --dot out/` | Exports parse trees as `.dot` and `.mmd` files into `out/` |
| `python -m unittest discover -s tests -v` | Runs all 21 unit tests |
| `python generate_docs.py` | Regenerates `docs/parse_trees.md` and `docs/evaluation_results.md` |
| `python main.py` | Prints the help text with all options |

### Examples

**Scan a single query**

```bash
python main.py -q "SELECT * FROM users WHERE id = '' OR '1'='1'" --tree --compare
```

**Scan several queries at once**

```bash
python main.py -q "SELECT * FROM users WHERE id = 5" -q "SELECT * FROM users WHERE id = 5 OR 1=1"
```

**Render an exported tree as an image (needs Graphviz)**

```bash
python main.py -q "SELECT * FROM users WHERE id = '' OR '1'='1'" --dot out/
dot -Tpng out/query_1.dot -o out/query_1.png
```

> **Windows note:** put the whole query in double quotes and use single quotes inside it, as in the examples above.

### Suggested live-demo order

1. `python main.py --sample --tree`: normal vs injected parse trees
2. `python main.py --evaluate`: grammar 10/10 vs blacklist 7/10
3. `python main.py --bypass`: attacks the blacklist misses
4. `python main.py --sqlite-demo`: what each attack does to a real database
5. `python main.py --interactive`: let the audience type their own query

---

## 7. Expected Output

### Sample queries (`python main.py --sample`)

```
Query 1: SELECT * FROM users WHERE id = '5'
  SAFE - WHERE has single equality condition
  Parse tree: WHERE → condition → (id = '5')

Query 2: SELECT * FROM users WHERE id = '' OR '1'='1'
  INJECTION DETECTED
    [OR_BRANCH] WHERE clause contains unexpected OR branch: OR → (id = '') │ ('1' = '1')
    [TAUTOLOGY] Tautology pattern ('1' = '1') - constant comparison with no column
  Parse tree: WHERE → OR → (id = '') │ ('1' = '1')

Query 3: SELECT * FROM users WHERE id = '' OR 1=1--
  INJECTION DETECTED
    [COMMENT] SQL comment '--' truncates / hides part of the query
    [OR_BRANCH] WHERE clause contains unexpected OR branch: OR → (id = '') │ (1 = 1)
    [TAUTOLOGY] Tautology pattern (1 = 1) - constant comparison with no column
  Parse tree: WHERE → OR → (id = '') │ (1 = 1)

Summary: 2 of 3 queries flagged as injection.
```

### sqlite3 demo (`python main.py --sqlite-demo`), excerpt

```
Tautology  (dump all rows)
  SELECT username, email FROM users WHERE id = 1 OR 1=1
  Scanner verdict : INJECTION DETECTED
  WITHOUT scanner : 3 row(s) returned -> [('alice', ...), ('bob', ...), ('admin', ...)]
  WITH scanner    : BLOCKED - query never reaches the database
```

The demo uses a throw-away in-memory database. It never touches any real data.

---

## 8. Test Cases

### Unit tests

```bash
python -m unittest discover -s tests -v
```

Expected result: `Ran 21 tests ... OK`

| Test class | Tests | What is checked |
|---|---|---|
| `LexerTests` | 4 | Token types, empty string and escaped quote (`''`), unterminated string, comment tokens |
| `ParserTests` | 5 | Normal tree shape, injected tree contains `Or`, precedence (`AND` binds tighter than `OR`), syntax error, stacked query |
| `DetectorTests` | 8 | The 3 brief samples, no-`WHERE` query is safe, `AND` allowed by default but flagged under `--strict`, unterminated quote, `UNION`, contradiction probe, string/number coercion (`'1' = 1`), semicolon inside a string is safe |
| `DatasetTests` | 4 | All 10 normal queries are SAFE, all 10 injected queries are detected, bypass queries beat the blacklist but not the grammar, the blacklist false positive |

### Test datasets (`data/`)

| File | Contents | Expected grammar verdict |
|---|---|---|
| `normal_queries.txt` | 10 legitimate queries (equality, `AND`, `LIKE`, `IN`, `ORDER BY`, `LIMIT`, escaped quote, semicolon inside a string) | All SAFE |
| `injected_queries.txt` | 10 injected queries (tautology, comment, stacked, `UNION`, blind probe, case and spacing tricks) | All INJECTION DETECTED |
| `bypass_queries.txt` | 5 injections crafted to slip past the keyword blacklist | All INJECTION DETECTED |

### Manual test queries

```bash
python main.py -q "SELECT * FROM users WHERE id = 1 OR 1=1"
python main.py -q "SELECT * FROM users WHERE id = 1; DROP TABLE users"
python main.py -q "SELECT * FROM users WHERE id = 1 UNION/**/SELECT username, password FROM admin"
python main.py -q "SELECT * FROM users WHERE name = 'O''Brien'"
python main.py -q "SELECT * FROM notes WHERE text = 'buy milk; call mom'"
```

---

## 9. The Grammar

Terminals are in `UPPERCASE` or quotes. `|` means alternative, `( )*` means zero or more, `[ ]` means optional.

```
query        → select_stmt ( UNION [ALL] select_stmt )* [ ";" ]
select_stmt  → SELECT select_list FROM table
               [ WHERE condition ]
               [ ORDER BY column [ ASC | DESC ] ]
               [ LIMIT NUMBER ]
select_list  → "*" | column ( "," column )*
table        → IDENT
column       → IDENT                      (may be table.column)

condition    → and_expr ( OR and_expr )*
and_expr     → not_expr ( AND not_expr )*
not_expr     → NOT not_expr | primary
primary      → "(" condition ")" | comparison
comparison   → operand cmp_op operand
             | operand LIKE operand
             | operand IN "(" literal ( "," literal )* ")"
operand      → column | literal
literal      → NUMBER | STRING
cmp_op       → "=" | "<>" | "!=" | "<" | ">" | "<=" | ">="
```

### Why the grammar is layered

The obvious grammar `condition → condition OR condition | condition AND condition | comparison` is **ambiguous**. The expression `a=1 OR b=2 AND c=3` has two different parse trees. A scanner that reasons about tree structure needs exactly one tree per query. Splitting the rules into `condition → and_expr → not_expr → primary` encodes precedence (`NOT` > `AND` > `OR`) and makes the grammar **unambiguous**.

### Normal vs injected parse tree

**Normal:** `SELECT * FROM users WHERE id = '5'`

```
Where
└── Comparison (id = '5')
```

**Injected:** `SELECT * FROM users WHERE id = '' OR '1'='1'`

```
Where
└── Or
    ├── Comparison (id = '')
    └── Comparison ('1' = '1')     ← tautology, never intended by the developer
```

To a keyword filter the two queries look almost identical. The **trees** are different, and that is what the detector uses.

Full details: `docs/grammar.md` and `docs/parse_trees.md`.

---

## 10. Detection Rules

Implemented in `sqli/detector.py`.

| Rule | Trigger | Typical attack |
|---|---|---|
| `LEXICAL` | Unterminated string or block comment | `' OR 'a'='a` leaving a quote open |
| `COMMENT` | `--`, `#` or `/* */` token | `admin'--` |
| `PARSE_ERROR` | Token stream cannot be derived from the CFG | Malformed or tampered query |
| `STACKED` | Another statement after `;` | `; DROP TABLE users` |
| `UNION` | Second `SELECT` branch in the tree | `UNION SELECT username, password ...` |
| `OR_BRANCH` | `Or` node inside `WHERE` | `' OR '1'='1` |
| `AND_BRANCH` | `And` node inside `WHERE` (only with `--strict`) | `AND 1=1` |
| `TAUTOLOGY` | Literal-vs-literal comparison that is true (`1=1`, `'a'='a'`, `2>1`), or a column compared with itself | `OR 1=1` |
| `CONTRADICTION` | Literal-vs-literal comparison that is false | `AND 1=2` (blind-SQLi probe) |

A query is reported as **INJECTION DETECTED** if at least one rule fires, and the explanation lists every rule that fired.

---

## 11. Evaluation: Grammar vs Blacklist

Run `python main.py --evaluate` to reproduce this.

| Detector | Injections caught (of 10) | False positives (of 10 normal) |
|---|---|---|
| **Grammar scanner** | **10 / 10** | **0 / 10** |
| Keyword blacklist | 7 / 10 | 1 / 10 |

### Injections the blacklist misses (the grammar scanner catches all of them)

| Query | Why the blacklist misses it |
|---|---|
| `... WHERE id = 5 AND 1=2` | Blind probe; no banned substring |
| `... WHERE id = 1 oR  2 = 2` | Different case, extra spaces and a tautology other than `1=1` |
| `... id = 1 UNION/**/SELECT ...` | A comment is used in place of the space, so `union select` never matches |

### False positive of the blacklist

`SELECT * FROM notes WHERE text = 'buy milk; call mom'` is a perfectly legitimate query. The blacklist blocks it because it contains `;`. The grammar scanner sees that the semicolon is inside a string literal and allows it.

**Why the grammar wins:** the blacklist matches *text*, so spacing, case and comments fool it. The grammar scanner matches *structure*, which an attacker cannot hide without breaking the injection itself.

Full tables: `docs/evaluation_results.md`.

---

## 12. Policy and Configuration

What the application *expects* its `WHERE` clause to look like is controlled by the `Policy` class in `sqli/detector.py`:

| Option | Default | Meaning |
|---|---|---|
| `allow_or` | `False` | A normal lookup query never needs `OR`, so any `OR` branch is flagged |
| `allow_and` | `True` | Plain `AND` chains of ordinary conditions are allowed |
| `allow_union` | `False` | Extra `UNION SELECT` branches are flagged |
| `allow_comments` | `False` | SQL comments are flagged |

The `--strict` command-line flag sets `allow_and=False`, so every boolean branch in `WHERE` is flagged.

To use the scanner from your own code:

```python
from sqli import scan, Policy

result = scan("SELECT * FROM users WHERE id = '' OR '1'='1'")
print(result.verdict)       # INJECTION DETECTED
print(result.rules)         # ['OR_BRANCH', 'TAUTOLOGY']
print(result.explanation)   # human-readable reasons

# a query that legitimately needs OR can use a custom policy
policy = Policy(allow_or=True)
scan("SELECT * FROM users WHERE id = 1 OR id = 2", policy)
```

---

## 13. Mapping to the Project Brief

| Objective / deliverable | Where it is satisfied |
|---|---|
| Write a CFG for basic `SELECT` SQL | `docs/grammar.md`, `sqli/parser.py` |
| Parse a normal and an injected query by hand, showing different trees | `docs/parse_trees.md` |
| Implement a SQL parser in Python | `sqli/lexer.py`, `sqli/parser.py`, `sqli/tree.py` |
| Detect unexpected `OR`/`AND` branches in `WHERE` | `sqli/detector.py` (`OR_BRANCH`, `AND_BRANCH`, `TAUTOLOGY`) |
| Compare with a blacklist and show it can be bypassed | `sqli/blacklist.py`, `--evaluate`, `--bypass`, `docs/evaluation_results.md` |
| Test 10 normal + 10 injected queries | `data/*.txt`, `tests/test_scanner.py` |
| Use `sqlite3` to show the actual query effect | `python main.py --sqlite-demo` |
| Slides: grammar detection vs blacklisting | `docs/slides_outline.md` |
| **Final deliverable:** a SQL scanner that flags injections by parse-tree structure and explains why | `main.py` |

---

## 14. Team and Contributions

| Member | Name | Role | Files |
|---|---|---|---|
| **Member 1** | Priyadarshini M | SQL CFG + hand parse trees | `docs/grammar.md`, `docs/parse_trees.md` |
| **Member 2** | Poojith B Gowda | Python SQL parser | `sqli/lexer.py`, `sqli/parser.py`, `sqli/tree.py` |
| **Member 3** | Kiran S V | Structural anomaly detector | `sqli/detector.py` |
| **Member 4** | Kushagra Sharma | Blacklist bypass demo + slides | `sqli/blacklist.py`, `sqli/evaluate.py`, `data/*.txt`, `docs/slides_outline.md` |

The commit history of this repository records each member's individual contribution.

### Presentation split

| Slides | Presenter |
|---|---|
| 3 to 5 (theory, grammar, parse trees) | Member 1: Priyadarshini M |
| 6 (architecture, lexer and parser) | Member 2: Poojith B Gowda |
| 7 to 8 (detection rules, live demo) | Member 3: Kiran S V |
| 9 to 10 (blacklist vs grammar, conclusion) | Member 4: Kushagra Sharma |

All four members are prepared to answer questions on any part of the project.

---

## 15. Limitations

- The grammar covers a **subset** of SQL (single-table `SELECT`). Real WAFs need dialect-specific grammars.
- Subqueries and hex literals such as `0x31` are not in the grammar. They are rejected as `PARSE_ERROR`, which errs on the safe side.
- A legitimate `OR` query (`WHERE a = 1 OR a = 2`) is flagged under the default policy. Use `Policy(allow_or=True)` for applications that need it.
- The scanner needs the full query text. It cannot see inside values that are encoded (URL-encoding, hex), so those must be decoded before scanning.
- The lexer is a hand-written DFA-style scanner built with regular expressions, not an explicit transition table.
- Constant-comparison checks do not account for a leading `NOT`, so `NOT (1=2)` is reported as `CONTRADICTION` although it is always true. It is still flagged.
- **The true fix is parameterized queries (prepared statements)**, where the query structure cannot change at all. This scanner is a defence-in-depth layer.

---

## 16. Troubleshooting

| Problem | Fix |
|---|---|
| `python` is not recognised | Use `python3`, or install Python from python.org and tick "Add to PATH" |
| `ModuleNotFoundError: No module named 'sqli'` | Run commands from the project root folder (the one containing `main.py`) |
| Box-drawing characters show as `?` | Use a UTF-8 terminal; on Windows run `chcp 65001` first |
| Query with quotes fails on Windows | Wrap the whole query in double quotes and use single quotes inside |
| `dot` command not found | Install Graphviz, or paste the `.mmd` Mermaid output into draw.io (Arrange, Insert, Advanced, Mermaid) |
| Tests not found | Run `python -m unittest discover -s tests -v` from the project root |

---

*Theory of Computation (BIS503) · Group 13 · Mini Project 13*
