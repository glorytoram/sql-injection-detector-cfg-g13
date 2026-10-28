# Context-Free Grammar for SQL Injection Detection

## 1. Introduction

A Context-Free Grammar (CFG) is a set of production rules used to describe the structure of a language.

In this project, CFG is used to describe SQL SELECT queries and identify suspicious structures associated with SQL injection attacks.

## 2. Grammar Rules

```text
query       -> select_stmt
select_stmt -> SELECT select_list FROM table WHERE condition
condition   -> and_expr (OR and_expr)*
and_expr    -> not_expr (AND not_expr)*
not_expr    -> NOT not_expr | primary
primary     -> (condition) | comparison
comparison  -> operand operator operand
operand     -> column | NUMBER | STRING

operator    -> = | != | < | > | <= | >=
select_list -> * | column_list
column_list -> column | column , column_list
table       -> identifier
column      -> identifier
identifier  -> letter (letter | digit | _)*
```

## 3. Ambiguity Discussion

SQL expressions containing both `AND` and `OR` can be interpreted differently if operator precedence is not defined clearly.

In this grammar, `and_expr` groups expressions connected by `AND`, while `condition` combines these expressions using `OR`. Therefore, `AND` has higher precedence than `OR`.

The `not_expr` rule handles the `NOT` operator, and parentheses allow conditions to be grouped explicitly.

These rules help the parser build a consistent parse tree for supported SQL expressions.

## 4. Detection Rules

The SQL injection detector analyzes SQL queries using the grammar and detection techniques implemented in the project.

1. **Lexical Analysis:** Identifies SQL keywords, identifiers, operators, strings, and numbers.
2. **Syntax Validation:** Checks whether a query follows the supported grammar.
3. **Structural Analysis:** Examines the query structure for suspicious patterns.
4. **Detection Result:** Reports the result based on the checks implemented by the detector.

A query that follows the grammar is not necessarily safe, and a syntax error alone does not prove an SQL injection attack. The detector's results depend on the rules and techniques implemented in the project.
