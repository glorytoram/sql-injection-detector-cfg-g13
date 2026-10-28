"""
Lexer (scanner) for the mini SQL language.

The lexer is a hand-written DFA-style scanner: it reads the query one character
at a time and groups characters into tokens (KEYWORD, IDENT, NUMBER, STRING, ...).
The *parser* (parser.py) then checks the token stream against the CFG.
"""
import re
from dataclasses import dataclass

KEYWORDS = {
    "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "LIKE", "IN",
    "ORDER", "BY", "ASC", "DESC", "LIMIT", "UNION", "ALL",
}

_NUMBER = re.compile(r"\d+(?:\.\d+)?")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?")
_TWO_CHAR_OPS = ("<=", ">=", "<>", "!=")
_ONE_CHAR_OPS = "=<>"


class LexError(Exception):
    """Raised when the query cannot even be split into valid tokens."""

    def __init__(self, message, pos):
        super().__init__(message)
        self.message = message
        self.pos = pos


@dataclass(frozen=True)
class Token:
    type: str    # KEYWORD IDENT NUMBER STRING OP STAR COMMA LPAREN RPAREN SEMI COMMENT EOF
    value: str   # normalised value (keywords upper-cased, string contents un-quoted)
    pos: int     # character offset in the original query
    raw: str = ""  # exact source text

    def describe(self):
        if self.type == "EOF":
            return "end of query"
        return repr(self.raw or self.value)


def tokenize(sql):
    tokens = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]

        if c.isspace():
            i += 1
            continue

        # ---- comments (classic injection tool: they cut off the rest of the query)
        if sql.startswith("--", i) or c == "#":
            j = sql.find("\n", i)
            j = n if j == -1 else j
            tokens.append(Token("COMMENT", sql[i:j], i, sql[i:j]))
            i = j
            continue
        if sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            if j == -1:
                raise LexError("Unterminated block comment", i)
            tokens.append(Token("COMMENT", sql[i:j + 2], i, sql[i:j + 2]))
            i = j + 2
            continue

        # ---- string literals ('' inside a string is an escaped quote)
        if c in ("'", '"'):
            quote, j, buf = c, i + 1, []
            while True:
                if j >= n:
                    raise LexError(
                        f"Unterminated string literal (quote opened at position {i} is never closed)", i)
                if sql[j] == quote:
                    if j + 1 < n and sql[j + 1] == quote:
                        buf.append(quote)
                        j += 2
                        continue
                    break
                buf.append(sql[j])
                j += 1
            tokens.append(Token("STRING", "".join(buf), i, sql[i:j + 1]))
            i = j + 1
            continue

        # ---- numbers (a leading '-' is a sign only where an operand may start)
        prev = tokens[-1].type if tokens else None
        if c == "-" and i + 1 < n and sql[i + 1].isdigit() and prev not in ("NUMBER", "STRING", "IDENT", "RPAREN"):
            m = _NUMBER.match(sql, i + 1)
            tokens.append(Token("NUMBER", "-" + m.group(), i, "-" + m.group()))
            i = m.end()
            continue
        if c.isdigit():
            m = _NUMBER.match(sql, i)
            tokens.append(Token("NUMBER", m.group(), i, m.group()))
            i = m.end()
            continue

        # ---- identifiers / keywords
        if c.isalpha() or c == "_":
            m = _IDENT.match(sql, i)
            word = m.group()
            if word.upper() in KEYWORDS:
                tokens.append(Token("KEYWORD", word.upper(), i, word))
            else:
                tokens.append(Token("IDENT", word, i, word))
            i = m.end()
            continue

        # ---- operators and punctuation
        if sql[i:i + 2] in _TWO_CHAR_OPS:
            tokens.append(Token("OP", sql[i:i + 2], i, sql[i:i + 2]))
            i += 2
            continue
        if c in _ONE_CHAR_OPS:
            tokens.append(Token("OP", c, i, c))
        elif c == "*":
            tokens.append(Token("STAR", c, i, c))
        elif c == ",":
            tokens.append(Token("COMMA", c, i, c))
        elif c == "(":
            tokens.append(Token("LPAREN", c, i, c))
        elif c == ")":
            tokens.append(Token("RPAREN", c, i, c))
        elif c == ";":
            tokens.append(Token("SEMI", c, i, c))
        else:
            raise LexError(f"Unexpected character {c!r} at position {i}", i)
        i += 1

    tokens.append(Token("EOF", "", n, ""))
    return tokens
