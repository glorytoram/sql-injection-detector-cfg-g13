"""
Recursive-descent parser for a small SQL SELECT language.

Grammar (see docs/grammar.md for the full discussion). The condition rules are
layered by precedence, which makes the grammar UNAMBIGUOUS:

    query       -> select_stmt ( UNION [ALL] select_stmt )* [ ';' ]
    select_stmt -> SELECT select_list FROM table [ WHERE condition ]
                   [ ORDER BY column [ASC|DESC] ] [ LIMIT NUMBER ]
    select_list -> '*' | column ( ',' column )*
    condition   -> and_expr ( OR and_expr )*
    and_expr    -> not_expr ( AND not_expr )*
    not_expr    -> NOT not_expr | primary
    primary     -> '(' condition ')' | comparison
    comparison  -> operand cmp_op operand
                 | operand LIKE operand
                 | operand IN '(' literal ( ',' literal )* ')'
    operand     -> column | NUMBER | STRING
"""
from .tree import Node


class ParseError(Exception):
    def __init__(self, message, token=None, kind="PARSE_ERROR"):
        super().__init__(message)
        self.message = message
        self.token = token
        self.kind = kind  # PARSE_ERROR | STACKED_QUERY


class Parser:
    def __init__(self, tokens):
        # Comments are not part of the grammar; the detector reports them separately.
        self.tokens = [t for t in tokens if t.type != "COMMENT"]
        self.i = 0

    # ---- helpers -----------------------------------------------------------
    def peek(self):
        return self.tokens[self.i]

    def advance(self):
        tok = self.tokens[self.i]
        if tok.type != "EOF":
            self.i += 1
        return tok

    def at_kw(self, *names):
        t = self.peek()
        return t.type == "KEYWORD" and t.value in names

    def expect_kw(self, name):
        if not self.at_kw(name):
            self.fail(f"Expected keyword {name}")
        return self.advance()

    def expect(self, ttype, what):
        if self.peek().type != ttype:
            self.fail(f"Expected {what}")
        return self.advance()

    def fail(self, message, kind="PARSE_ERROR"):
        t = self.peek()
        raise ParseError(f"{message} but found {t.describe()} at position {t.pos}", t, kind)

    # ---- grammar rules -----------------------------------------------------
    def parse(self):
        root = Node("Query", [self.select_stmt()])
        while self.at_kw("UNION"):
            self.advance()
            if self.at_kw("ALL"):
                self.advance()
            root.children.append(Node("Union", [self.select_stmt()]))
        if self.peek().type == "SEMI":
            self.advance()
            if self.peek().type != "EOF":
                self.fail("Extra statement after ';' (stacked query)", kind="STACKED_QUERY")
        if self.peek().type != "EOF":
            self.fail("Expected end of query")
        return root

    def select_stmt(self):
        node = Node("Select")
        self.expect_kw("SELECT")
        node.children.append(self.select_list())
        self.expect_kw("FROM")
        table = self.expect("IDENT", "a table name")
        node.children.append(Node("From", [Node("Table", text=table.value)]))
        if self.at_kw("WHERE"):
            self.advance()
            node.children.append(Node("Where", [self.condition()]))
        if self.at_kw("ORDER"):
            self.advance()
            self.expect_kw("BY")
            col = self.expect("IDENT", "a column name")
            order = Node("OrderBy", [Node("Column", text=col.value)])
            if self.at_kw("ASC", "DESC"):
                order.children.append(Node("Direction", text=self.advance().value))
            node.children.append(order)
        if self.at_kw("LIMIT"):
            self.advance()
            num = self.expect("NUMBER", "a number")
            node.children.append(Node("Limit", [Node("Number", text=num.value)]))
        return node

    def select_list(self):
        node = Node("SelectList")
        if self.peek().type == "STAR":
            self.advance()
            node.children.append(Node("Star", text="*"))
            return node
        node.children.append(Node("Column", text=self.expect("IDENT", "a column name or '*'").value))
        while self.peek().type == "COMMA":
            self.advance()
            node.children.append(Node("Column", text=self.expect("IDENT", "a column name").value))
        return node

    def condition(self):
        items = [self.and_expr()]
        while self.at_kw("OR"):
            self.advance()
            items.append(self.and_expr())
        return items[0] if len(items) == 1 else Node("Or", items)

    def and_expr(self):
        items = [self.not_expr()]
        while self.at_kw("AND"):
            self.advance()
            items.append(self.not_expr())
        return items[0] if len(items) == 1 else Node("And", items)

    def not_expr(self):
        if self.at_kw("NOT"):
            self.advance()
            return Node("Not", [self.not_expr()])
        return self.primary()

    def primary(self):
        if self.peek().type == "LPAREN":
            self.advance()
            inner = self.condition()
            self.expect("RPAREN", "')'")
            return inner
        return self.comparison()

    def comparison(self):
        left = self.operand()
        t = self.peek()
        if t.type == "OP":
            self.advance()
            right = self.operand()
            return Node("Comparison", [left, Node("Op", text=t.value), right])
        if self.at_kw("LIKE"):
            self.advance()
            right = self.operand()
            return Node("Comparison", [left, Node("Op", text="LIKE"), right])
        if self.at_kw("IN"):
            self.advance()
            self.expect("LPAREN", "'('")
            values = Node("ValueList", [self.literal()])
            while self.peek().type == "COMMA":
                self.advance()
                values.children.append(self.literal())
            self.expect("RPAREN", "')'")
            return Node("In", [left, values])
        self.fail("Expected a comparison operator (=, <, >, <=, >=, <>, !=, LIKE, IN)")

    def operand(self):
        t = self.peek()
        if t.type == "IDENT":
            self.advance()
            return Node("Column", text=t.value)
        return self.literal()

    def literal(self):
        t = self.peek()
        if t.type == "NUMBER":
            self.advance()
            return Node("Number", text=t.value)
        if t.type == "STRING":
            self.advance()
            return Node("String", text=t.raw if t.raw else f"'{t.value}'")
        self.fail("Expected a column, number or string")


def parse(tokens):
    return Parser(tokens).parse()
