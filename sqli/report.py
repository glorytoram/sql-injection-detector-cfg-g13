"""Console formatting helpers."""
from .detector import compact, _where_of, _selects
from .tree import render_ascii


def where_path(result):
    """The 'WHERE → OR → (a) │ (b)' line used in the project's sample output."""
    if result.tree is None:
        return None
    where = _where_of(_selects(result.tree)[0])
    if where is None:
        return "(no WHERE clause)"
    cond = where.children[0]
    if cond.label in ("Comparison", "In"):
        return "WHERE → condition → " + compact(cond)
    return "WHERE → " + compact(cond)


def format_result(res, label, show_tree=False):
    lines = [f"{label}: {res.query}"]
    if res.injection:
        lines.append(f"  INJECTION DETECTED")
        for f in res.findings:
            lines.append(f"    [{f.rule}] {f.message}")
    else:
        lines.append(f"  SAFE - {res.safe_reason}")
    path = where_path(res)
    if path:
        lines.append(f"  Parse tree: {path}")
    if show_tree and res.tree is not None:
        lines.append("  Full parse tree:")
        lines.extend("    " + l for l in render_ascii(res.tree).splitlines())
    return "\n".join(lines)
