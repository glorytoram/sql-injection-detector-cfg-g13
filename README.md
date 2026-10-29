# SQL Injection Detector via Grammar Analysis

**Theory of Computation (BIS503) | Section B | Mini Project 13 | Group 13**

| | |
|---|---|
| **Theory concept** | Context-Free Grammar (CFG): ambiguity and parse-tree analysis |
| **Application** | Cybersecurity: Web Application Firewall (WAF) logic |
| **Language** | Python 3.8+ (standard library only, nothing to install) |

## Team

| Member | Role | Main files |
|---|---|---|
| Priyadarshini M | SQL grammar (CFG) and hand-drawn parse trees | `docs/grammar.md`, `docs/parse_trees.md`, `docs/images/` |
| Poojith B Gowda | Python SQL lexer and parser | `sqli/lexer.py`, `sqli/parser.py`, `sqli/tree.py` |
| Kiran S V | Structural anomaly detector | `sqli/detector.py` |
| Kushagra Sharma (`@glorytoram`) | Blacklist bypass demo, tests and slides | `sqli/blacklist.py`, `sqli/evaluate.py`, `data/`, `tests/`, `docs/slides_outline.md` |

---

## 1. The idea in one minute

An SQL injection attack works by **changing the structure** of a query.

A normal query has one simple condition in its `WHERE` clause:

```sql
SELECT * FROM users WHERE id = '5'
```

An injected query gets an extra `OR` branch the programmer never wrote:

```sql
SELECT * FROM users WHERE id = '' OR '1'='1'
```

Because `'1'='1'` is always true, this returns **every row**. The two queries have **different parse trees**:

| Normal query | Injected query |
|---|---|
| ![normal](docs/images/normal_query.png) | ![injected](docs/images/suspicious_query.png) |

Our program parses the query with a Context-Free Grammar, looks at the parse tree, and flags it when the structure is not what a normal query should look like. This is stronger than a **keyword blacklist** (searching for words like `OR 1=1`), which attackers get around with extra spaces, different case or comments.

## 2. How it works

```
 SQL query  ->  Lexer  ->  Parser (CFG)  ->  Tree analysis  ->  Verdict + reason
               tokens     parse tree        looks for OR,        SAFE or
                                            UNION, comments,     INJECTION DETECTED
                                            tautologies ...
```

| Step | File | What it does |
|---|---|---|
| 1. Lexer | `sqli/lexer.py` | Reads characters and groups them into tokens (keyword, name, number, string...). A DFA-style scanner. |
| 2. Parser | `sqli/parser.py` | Checks the tokens against our SQL grammar and builds a parse tree. |
| 3. Detector | `sqli/detector.py` | Walks the tree and applies the detection rules below. |
| 4. Report | `sqli/report.py` | Prints the verdict and the reason. |

The grammar is written so that `AND` binds tighter than `OR`. That makes it **unambiguous**: every query has exactly one parse tree. The grammar is in [`docs/grammar.md`](docs/grammar.md).

### Detection rules

| Rule | Meaning | Example |
|---|---|---|
| `OR_BRANCH` | An unexpected `OR` in `WHERE` | `id = '' OR '1'='1'` |
| `TAUTOLOGY` | A comparison that is always true | `1=1`, `'a'='a'` |
| `CONTRADICTION` | A comparison that is always false (blind probe) | `AND 1=2` |
| `UNION` | A second `SELECT` glued on to steal data | `UNION SELECT username, password ...` |
| `STACKED` | A second statement after `;` | `; DROP TABLE users` |
| `COMMENT` | `--`, `#` or `/* */` hides the rest of the query | `admin'--` |
| `LEXICAL` | A string or comment that is never closed | `id = '5` |
| `PARSE_ERROR` | The query does not fit the grammar | `WHERE id = 1 OR` |
| `AND_BRANCH` | Any `AND` in `WHERE` (only with `--strict`) | `id = 1 AND x = 2` |

## 3. How to run (Windows CMD)

You need Python 3.8 or newer. Check with `python --version` (use `python3` if that is what works on your machine).

```cmd
git clone https://github.com/glorytoram/sql-injection-detector-cfg-g13.git
cd sql-injection-detector-cfg-g13
python main.py --sample
```

There is nothing to build or install. Run all commands from the project folder.

| Command | What it does |
|---|---|
| `python main.py --sample` | Scans the 3 sample queries from the project brief |
| `python main.py --sample --tree` | Same, and prints the full parse tree of each query |
| `python main.py --evaluate` | 10 normal + 10 injected queries: grammar vs blacklist |
| `python main.py --bypass` | Attacks that beat the blacklist but are caught by the grammar |
| `python main.py --sqlite-demo` | Runs the queries on a real in-memory sqlite3 database |
| `python main.py -q "SELECT * FROM users WHERE id = 1 OR 1=1"` | Scans one query you type |
| `python main.py -q "..." --tree --compare` | Also shows the parse tree and the blacklist verdict |
| `python main.py --file data/injected_queries.txt` | Scans every query in a file (one per line) |
| `python main.py --interactive` | Type queries one by one (empty line to quit) |
| `python main.py --sample --strict` | Strict mode: flags any `AND` as well |
| `python main.py --sample --dot out` | Exports parse trees as Graphviz `.dot` and Mermaid `.mmd` |
| `python -m unittest discover -v` | Runs the 21 unit tests |
| `python main.py` | Shows the help text |

On Windows put the whole query in **double quotes** and use **single quotes inside** it.

### Suggested demo order

1. `python main.py --sample --tree` shows the normal and injected trees
2. `python main.py --evaluate` shows grammar 10/10 vs blacklist 7/10
3. `python main.py --bypass` shows the attacks the blacklist misses
4. `python main.py --sqlite-demo` shows what each attack does to a database
5. `python main.py --interactive` lets the audience type their own query

## 4. Sample output

Input (`python main.py --sample`):

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

## 5. Results: grammar vs keyword blacklist

From `python main.py --evaluate` (10 normal and 10 injected queries in `data/`):

| Detector | Injections caught (out of 10) | False alarms on normal queries (out of 10) |
|---|---|---|
| **Grammar scanner (ours)** | **10** | **0** |
| Keyword blacklist | 7 | 1 |

Injections the blacklist misses, but the grammar catches (`python main.py --bypass`):

| Attack | Why the blacklist misses it |
|---|---|
| `... WHERE id = 1 oR  2 = 2` | Different letter case, extra spaces, and a tautology other than `1=1` |
| `... WHERE id = 1 OR 'a'='a'` | A tautology the blacklist does not know |
| `... WHERE id = 1 UNION/**/SELECT ...` | A comment replaces the space, so `union select` never matches |
| `... WHERE id = 1 OR 5>3` | Not an equality test, so no banned pattern |
| `... WHERE id = 5 AND 1=2` | Blind probe with no banned word |

The blacklist also blocks the harmless query `SELECT * FROM notes WHERE text = 'buy milk; call mom'` because it contains `;`. The grammar scanner sees the `;` is inside a string and allows it.

**Why the grammar wins:** the blacklist matches *text*, so spacing, case and comments fool it. The grammar scanner checks *structure*, which an attacker cannot change without breaking the attack.

## 6. Project structure

```
sql-injection-detector-cfg-g13/
├── main.py              command-line program
├── generate_docs.py     regenerates docs/parse_trees.md and docs/evaluation_results.md
├── requirements.txt     (no packages needed)
├── sqli/                the program
│   ├── lexer.py         tokenizer
│   ├── parser.py        CFG parser -> parse tree
│   ├── tree.py          parse tree + export to text / DOT / Mermaid
│   ├── detector.py      structural detector (the scanner)
│   ├── blacklist.py     simple keyword blacklist, for comparison
│   ├── evaluate.py      grammar vs blacklist comparison
│   ├── sqlite_demo.py   real effect on a sqlite3 database
│   └── report.py        output formatting
├── data/                normal, injected and bypass test queries
├── tests/               21 unit tests
└── docs/                grammar, parse trees, results, slide outline, images
```

## 7. Tests

```cmd
python -m unittest discover -v
```

Expected: `Ran 21 tests ... OK`. They cover the lexer, the parser, the detector and the three query files in `data/` (all 10 normal queries are SAFE, all 10 injected and all 5 bypass queries are detected).

## 8. Limitations

- The grammar covers basic single-table `SELECT` queries only. Subqueries, functions like `COUNT(*)`, table aliases and `BETWEEN` are reported as `PARSE_ERROR`.
- A legitimate `WHERE a = 1 OR a = 2` is flagged under the default policy. The `Policy` class in `sqli/detector.py` can be changed for applications that need `OR`.
- Encoded input (URL-encoding, hex) must be decoded before scanning.
- The real defence against SQL injection is **parameterized queries (prepared statements)**. This scanner is an extra layer of protection.
