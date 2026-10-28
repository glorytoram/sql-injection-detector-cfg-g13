"""Parse-tree node + exporters (ASCII, Graphviz DOT, Mermaid)."""
from dataclasses import dataclass, field


@dataclass
class Node:
    label: str
    children: list = field(default_factory=list)
    text: str = ""  # lexeme for terminal nodes (column name, number, string, operator)

    def display(self):
        return f"{self.label}: {self.text}" if self.text else self.label

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()


def render_ascii(node, prefix="", is_last=True, is_root=True):
    """Return the tree as a multi-line string using box-drawing characters."""
    if is_root:
        lines = [node.display()]
        child_prefix = ""
    else:
        lines = [prefix + ("└── " if is_last else "├── ") + node.display()]
        child_prefix = prefix + ("    " if is_last else "│   ")
    for idx, child in enumerate(node.children):
        lines.append(render_ascii(child, child_prefix, idx == len(node.children) - 1, False))
    return "\n".join(lines)


def _escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def to_dot(root, name="parse_tree"):
    """Graphviz DOT source (render with `dot -Tpng` or paste into an online viewer)."""
    lines = [f"digraph {name} {{", "  node [shape=box, fontname=Helvetica];"]
    counter = [0]

    def visit(node):
        my_id = f"n{counter[0]}"
        counter[0] += 1
        lines.append(f'  {my_id} [label="{_escape(node.display())}"];')
        for child in node.children:
            child_id = visit(child)
            lines.append(f"  {my_id} -> {child_id};")
        return my_id

    visit(root)
    lines.append("}")
    return "\n".join(lines)


def to_mermaid(root):
    """Mermaid flowchart source (draw.io: Arrange > Insert > Advanced > Mermaid)."""
    lines = ["graph TD"]
    counter = [0]

    def visit(node):
        my_id = f"n{counter[0]}"
        counter[0] += 1
        label = node.display().replace('"', "'")
        lines.append(f'  {my_id}["{label}"]')
        for child in node.children:
            child_id = visit(child)
            lines.append(f"  {my_id} --> {child_id}")
        return my_id

    visit(root)
    return "\n".join(lines)
