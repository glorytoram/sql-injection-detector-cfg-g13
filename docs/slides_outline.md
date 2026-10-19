# Slide outline - "Grammar detection vs keyword blacklisting" (10 slides)

1. **Title** - SQL Injection Detector via Grammar Analysis (BIS503, Project 13, team names)
2. **Problem** - SQL injection in one picture; OWASP Top 10; WAF role
3. **Theory recap** - CFG, derivation, parse tree, ambiguity (`docs/grammar.md`)
4. **Our SQL grammar** - the BNF; why it is layered (OR < AND < NOT) to be unambiguous
5. **Key idea** - injection changes the parse tree: normal vs injected tree side by side (`docs/parse_trees.md`)
6. **Architecture** - Lexer -> Parser (recursive descent) -> Structural analyser -> Verdict + explanation
7. **Detection rules** - table of rules (COMMENT, UNION, OR_BRANCH, TAUTOLOGY, ...)
8. **Live demo** - `python main.py --sample --tree`, then `python main.py --sqlite-demo`
9. **Blacklist vs grammar** - evaluation table (`docs/evaluation_results.md`): 10/10 vs 7/10, false positive on `'a;b'`; show the 2+ bypass queries
10. **Limitations & conclusion** - subset of SQL, encoded payloads, prepared statements are the real fix

Speaker split: Member 1 slides 3-5, Member 2 slide 6, Member 3 slide 7-8, Member 4 slide 9-10.
