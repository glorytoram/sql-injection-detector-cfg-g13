"""
Grammar-based SQL injection detector.

Idea: an injection changes the *grammatical structure* of the query. The detector
(1) tokenizes the query, (2) parses it with the CFG in parser.py, and (3) inspects
the resulting parse tree for structure the application never intended:

    LEXICAL      unterminated string / comment -> attacker broke out of a literal
    COMMENT      '--', '#', '/* */'            -> rest of the query is cut off
    PARSE_ERROR  query is not valid in the grammar (tampered structure)
    STACKED      a second statement after ';'  -> e.g. '; DROP TABLE users'
    UNION        a second SELECT glued on      -> data exfiltration
    OR_BRANCH    unexpected OR branch in WHERE -> classic  ' OR '1'='1
    AND_BRANCH   AND branch (only in strict policy)
    TAUTOLOGY    literal-vs-literal comparison that is always true (1=1, 'a'='a', 2>1)
    CONTRADICTION literal-vs-literal comparison that is always false (AND 1=2, blind probe)
"""
from dataclasses import dataclass, field
from typing import List, Optional

from .lexer import tokenize, LexError
from .parser import parse, ParseError
from .tree import Node


@dataclass
class Policy:
    """What the application EXPECTS its WHERE clause to look like."""
    allow_or: bool = False      # OR branches are never expected from a normal lookup query
    allow_and: bool = True      # AND of ordinary conditions is allowed (False = strict mode)
    allow_union: bool = False
    allow_comments: bool = False


@dataclass
class Finding:
    rule: str
    message: str


@dataclass
class ScanResult:
    query: str
    injection: bool
    findings: List[Finding] = field(default_factory=list)
    tree: Optional[Node] = None
    tokens: list = field(default_factory=list)
    safe_reason: str = ""

    @property
    def verdict(self):
        return "INJECTION DETECTED" if self.injection else "SAFE"

    @property
    def explanation(self):
        if self.injection:
            return "; ".join(f.message for f in self.findings)
        return self.safe_reason

    @property
    def rules(self):
        return [f.rule for f in self.findings]


# ---------------------------------------------------------------------------
# helpers on the parse tree
# ---------------------------------------------------------------------------
def _selects(tree):
    """All Select nodes of the query (the first one + every UNION branch)."""
    result = []
    for child in tree.children:
        result.append(child if child.label == "Select" else child.children[0])
    return result


def _where_of(select):
    for child in select.children:
        if child.label == "Where":
            return child
    return None


def _is_literal(node):
    return node.label in ("Number", "String")


def _value(node):
    """Python value of a literal node (strings have their quotes stripped)."""
    if node.label == "Number":
        return float(node.text)
    text = node.text
    return text[1:-1].replace(text[0] * 2, text[0]) if len(text) >= 2 else text


def _coerce_pair(a, b):
    if isinstance(a, float) and isinstance(b, float):
        return a, b
    if isinstance(a, str) and isinstance(b, str):
        return a, b
    try:  # SQL engines silently convert '1' <-> 1
        return float(a), float(b)
    except (TypeError, ValueError):
        return str(a), str(b)


def _truth(left, op, right):
    """Evaluate a literal-vs-literal comparison. Returns True / False / None (unknown)."""
    if op == "LIKE":
        return None
    a, b = _coerce_pair(_value(left), _value(right))
    return {
        "=": a == b, "<>": a != b, "!=": a != b,
        "<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b,
    }.get(op)


def compact(node):
    """One-line summary of a condition subtree, e.g.  OR → (id = '') │ ('1' = '1')."""
    if node.label == "Comparison":
        left, op, right = node.children
        return f"({left.text} {op.text} {right.text})"
    if node.label == "In":
        left, values = node.children
        return f"({left.text} IN [{', '.join(v.text for v in values.children)}])"
    if node.label in ("Or", "And"):
        parts = []
        for child in node.children:
            text = compact(child)
            parts.append(f"[{text}]" if child.label in ("Or", "And") else text)
        return f"{node.label.upper()} → " + " │ ".join(parts)
    if node.label == "Not":
        return "NOT → " + compact(node.children[0])
    return node.display()


def _safe_reason(tree):
    where = _where_of(_selects(tree)[0])
    if where is None:
        return "No WHERE clause - nothing user-controlled to tamper with"
    cond = where.children[0]
    if cond.label == "Comparison":
        op = cond.children[1].text
        kind = "equality" if op == "=" else "LIKE" if op == "LIKE" else "comparison"
        return f"WHERE has single {kind} condition"
    if cond.label == "In":
        return "WHERE has single IN-list condition"
    if cond.label == "And":
        return f"WHERE has {len(cond.children)} ordinary conditions joined by AND only"
    return "WHERE structure matches the expected shape"


# ---------------------------------------------------------------------------
# the scanner
# ---------------------------------------------------------------------------
def scan(query, policy=None):
    policy = policy or Policy()
    result = ScanResult(query=query, injection=False)

    # 1. lexical analysis -----------------------------------------------------
    try:
        tokens = tokenize(query)
    except LexError as e:
        result.findings.append(Finding(
            "LEXICAL", f"{e.message} - input broke out of / left open a string or comment"))
        result.injection = True
        return result
    result.tokens = tokens

    comments = [t for t in tokens if t.type == "COMMENT"]
    if comments and not policy.allow_comments:
        shown = ", ".join(repr(c.raw[:12] + ("..." if len(c.raw) > 12 else "")) for c in comments)
        result.findings.append(Finding(
            "COMMENT", f"SQL comment {shown} truncates / hides part of the query"))

    # 2. syntax analysis (CFG) ----------------------------------------------------
    try:
        tree = parse(tokens)
    except ParseError as e:
        rule = "STACKED" if e.kind == "STACKED_QUERY" else "PARSE_ERROR"
        prefix = "Stacked query" if rule == "STACKED" else "Query does not fit the expected SQL grammar"
        result.findings.append(Finding(rule, f"{prefix}: {e.message}"))
        result.injection = True
        return result
    result.tree = tree

    # 3. structural analysis of the parse tree ----------------------------------------
    if len(tree.children) > 1 and not policy.allow_union:
        result.findings.append(Finding(
            "UNION", "Extra UNION SELECT branch grafted onto the query (data exfiltration)"))

    for select in _selects(tree):
        where = _where_of(select)
        if where is None:
            continue
        for node in where.walk():
            if node.label == "Or" and not policy.allow_or:
                result.findings.append(Finding(
                    "OR_BRANCH", "WHERE clause contains unexpected OR branch: " + compact(node)))
            elif node.label == "And" and not policy.allow_and:
                result.findings.append(Finding(
                    "AND_BRANCH", "WHERE clause contains unexpected AND branch: " + compact(node)))
            elif node.label == "Comparison":
                left, op, right = node.children
                shown = f"{left.text} {op.text} {right.text}"
                if _is_literal(left) and _is_literal(right):
                    truth = _truth(left, op.text, right)
                    if truth is False:
                        result.findings.append(Finding(
                            "CONTRADICTION", f"Constant comparison {shown} is always false (blind-injection probe)"))
                    else:
                        result.findings.append(Finding(
                            "TAUTOLOGY", f"Tautology pattern ({shown}) - constant comparison with no column"))
                elif left.label == "Column" and right.label == "Column" and left.text == right.text:
                    result.findings.append(Finding(
                        "TAUTOLOGY", f"Tautology pattern ({shown}) - column compared with itself"))
            elif node.label == "In":
                left = node.children[0]
                if _is_literal(left):
                    result.findings.append(Finding(
                        "TAUTOLOGY", f"Constant IN-test on literal {left.text} - no column involved"))

    result.injection = bool(result.findings)
    if not result.injection:
        result.safe_reason = _safe_reason(tree)
    return result
