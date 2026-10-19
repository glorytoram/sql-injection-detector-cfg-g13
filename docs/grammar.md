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
