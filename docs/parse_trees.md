# SQL Injection Detection: Parse Trees

## 1. Introduction

A parse tree represents the grammatical structure of an SQL query.
In this project, parse trees help explain the differences between
normal SQL queries and queries containing suspicious conditions.

## 2. Normal SQL Query

Example:

SELECT * FROM users WHERE id = '5';

### Simplified Parse Tree

```text
Query
└── Select
    ├── SelectList
    │   └── Star (*)
    ├── From
    │   └── Table (users)
    └── Where
        └── Comparison
            ├── Column (id)
            ├── Operator (=)
            └── String ('5')
