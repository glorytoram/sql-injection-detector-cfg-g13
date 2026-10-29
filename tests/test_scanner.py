import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqli import scan, Policy, blacklist_scan
from sqli.lexer import tokenize, LexError
from sqli.parser import parse, ParseError
from sqli.evaluate import load_queries


class LexerTests(unittest.TestCase):
    def test_token_types(self):
        types = [t.type for t in tokenize("SELECT * FROM users WHERE id = '5'")]
        self.assertEqual(types, ["KEYWORD", "STAR", "KEYWORD", "IDENT", "KEYWORD", "IDENT", "OP", "STRING", "EOF"])

    def test_empty_string_and_escaped_quote(self):
        toks = tokenize("id = '' OR name = 'O''Brien'")
        strings = [t.value for t in toks if t.type == "STRING"]
        self.assertEqual(strings, ["", "O'Brien"])

    def test_unterminated_string(self):
        with self.assertRaises(LexError):
            tokenize("SELECT * FROM users WHERE id = '5")

    def test_comment_tokens(self):
        self.assertEqual([t.type for t in tokenize("1 -- x")][-2], "COMMENT")


class ParserTests(unittest.TestCase):
    def test_normal_tree_shape(self):
        tree = parse(tokenize("SELECT * FROM users WHERE id = '5'"))
        where = tree.children[0].children[2]
        self.assertEqual(where.label, "Where")
        self.assertEqual(where.children[0].label, "Comparison")

    def test_injected_tree_has_or(self):
        tree = parse(tokenize("SELECT * FROM users WHERE id = '' OR '1'='1'"))
        cond = tree.children[0].children[2].children[0]
        self.assertEqual(cond.label, "Or")
        self.assertEqual(len(cond.children), 2)

    def test_precedence_and_binds_tighter(self):
        tree = parse(tokenize("SELECT * FROM t WHERE a = 1 OR b = 2 AND c = 3"))
        cond = tree.children[0].children[2].children[0]
        self.assertEqual(cond.label, "Or")
        self.assertEqual(cond.children[1].label, "And")

    def test_syntax_error(self):
        with self.assertRaises(ParseError):
            parse(tokenize("SELECT FROM users"))

    def test_stacked(self):
        with self.assertRaises(ParseError) as ctx:
            parse(tokenize("SELECT * FROM users; DROP TABLE users"))
        self.assertEqual(ctx.exception.kind, "STACKED_QUERY")


class DetectorTests(unittest.TestCase):
    def test_brief_samples(self):
        q1 = scan("SELECT * FROM users WHERE id = '5'")
        q2 = scan("SELECT * FROM users WHERE id = '' OR '1'='1'")
        q3 = scan("SELECT * FROM users WHERE id = '' OR 1=1--")
        self.assertFalse(q1.injection)
        self.assertEqual(q1.safe_reason, "WHERE has single equality condition")
        self.assertTrue(q2.injection)
        self.assertIn("OR_BRANCH", q2.rules)
        self.assertTrue(q3.injection)
        self.assertIn("OR_BRANCH", q3.rules)
        self.assertIn("TAUTOLOGY", q3.rules)

    def test_no_where_is_safe(self):
        self.assertFalse(scan("SELECT * FROM users").injection)

    def test_and_allowed_by_default_but_not_strict(self):
        q = "SELECT * FROM t WHERE a = 1 AND b = 2"
        self.assertFalse(scan(q).injection)
        self.assertTrue(scan(q, Policy(allow_and=False)).injection)

    def test_unterminated_quote_flagged(self):
        self.assertTrue(scan("SELECT * FROM users WHERE name = 'x' OR 'a'='a").injection)

    def test_union_flagged(self):
        self.assertIn("UNION", scan("SELECT a FROM t UNION SELECT b FROM u").rules)

    def test_contradiction_probe(self):
        self.assertIn("CONTRADICTION", scan("SELECT * FROM t WHERE id = 5 AND 1=2").rules)

    def test_string_number_coercion(self):
        self.assertIn("TAUTOLOGY", scan("SELECT * FROM t WHERE id = 5 OR '1'=1").rules)

    def test_semicolon_inside_string_is_safe(self):
        self.assertFalse(scan("SELECT * FROM notes WHERE text = 'a;b'").injection)


class DatasetTests(unittest.TestCase):
    def test_all_normal_safe(self):
        for q in load_queries("normal_queries.txt"):
            self.assertFalse(scan(q).injection, q)

    def test_all_injected_detected(self):
        qs = load_queries("injected_queries.txt")
        self.assertEqual(len(qs), 10)
        for q in qs:
            self.assertTrue(scan(q).injection, q)

    def test_bypass_queries_beat_blacklist_but_not_grammar(self):
        qs = load_queries("bypass_queries.txt")
        self.assertGreaterEqual(len(qs), 2)
        for q in qs:
            self.assertFalse(blacklist_scan(q)[0], f"blacklist unexpectedly caught: {q}")
            self.assertTrue(scan(q).injection, q)

    def test_blacklist_false_positive(self):
        self.assertTrue(blacklist_scan("SELECT * FROM notes WHERE text = 'buy milk; call mom'")[0])


if __name__ == "__main__":
    unittest.main()
